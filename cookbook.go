//
// Copyright 2014, Sander van Harmelen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	// import hmac

	// import hashlib
	"crypto/sha256"

	"github.com/gorilla/mux"
)

func processCookbook(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if getEffectiveConfig("Mode", getChefOrgFromRequest(r)).(string) == "silent" && getEffectiveConfig("CommitChanges", getChefOrgFromRequest(r)).(bool) == false {
			p.ServeHTTP(w, r)
			return
		}

		cg, err := newChefGuard(r)
		if err != nil {
			errorHandler(w, fmt.Sprintf("Failed to create a new ChefGuard structure: %s", err), http.StatusInternalServerError)
			return
		}
		if r.Method != "DELETE" {
			body, err := dumpBody(r)
			if err != nil {
				errorHandler(w, fmt.Sprintf("Failed to get body from call to %s: %s", r.URL.String(), err), http.StatusBadRequest)
				return
			}
			if err := json.Unmarshal(body, &cg.Cookbook); err != nil {
				errorHandler(w, fmt.Sprintf("Failed to unmarshal body %s: %s", string(body), err), http.StatusBadRequest)
				return
			}
			if getEffectiveConfig("Mode", cg.ChefOrg).(string) != "silent" {
				if errCode, err := cg.checkCookbookFrozen(); err != nil {
					if strings.Contains(r.Header.Get("User-Agent"), "Ridley") {
						errCode = http.StatusConflict
					}
					errorHandler(w, err.Error(), errCode)
					return
				}
				if cg.Cookbook.Frozen {
					cg.CookbookPath = path.Join(cfg.Default.Tempdir, fmt.Sprintf("%s-%s", r.Header.Get("X-Ops-Userid"), cg.Cookbook.Name))
					if err := cg.processCookbookFiles(); err != nil {
						errorHandler(w, err.Error(), http.StatusBadRequest)
						return
					}
					defer func() {
						if err := os.RemoveAll(cg.CookbookPath); err != nil {
							WARNING.Printf("Failed to cleanup temp cookbook folder %s: %s", cg.CookbookPath, err)
						}
					}()
					if errCode, err := cg.validateCookbookStatus(); err != nil {
						errorHandler(w, err.Error(), errCode)
						return
					}
					if errCode, err := cg.tagAndPublishCookbook(); err != nil {
						errorHandler(w, err.Error(), errCode)
						return
					}
				}
			}
		}
		if getEffectiveConfig("CommitChanges", cg.ChefOrg).(bool) {
			details := cg.getCookbookChangeDetails(r)
			go cg.syncedGitUpdate(r.Method, details)
		}
		p.ServeHTTP(w, r)
	}
}

func (cg *ChefGuard) processCookbookFiles() error {
	if cg.ChefOrgID == nil {
		if err := cg.getOrganizationID(); err != nil {
			return fmt.Errorf("Failed to get organization ID for %s: %s", cg.ChefOrg, err)
		}
	}
	buf := new(bytes.Buffer)
	gw := gzip.NewWriter(buf)
	tw := tar.NewWriter(gw)

	client := http.DefaultClient

	if cfg.Chef.SSLNoVerify {
		client = &http.Client{Transport: insecureTransport}
	}

	// Let's first find and save the .gitignore and chefignore files
	for _, f := range cg.Cookbook.AllFiles {

		if f.Path == ".gitignore" || f.Path == "chefignore" {

			content, err := downloadCookbookFile(client, *cg.ChefOrgID, f.Checksum)
			if err != nil {
				return fmt.Errorf("Failed to dowload %s from the %s cookbook: %s", f.Path, cg.Cookbook.Name, err)
			}
			// Save .gitignore file for later use
			if f.Path == ".gitignore" {
				cg.GitIgnoreFile = content
			}
			// Save chefignore file for later use
			if f.Path == "chefignore" {
				cg.ChefIgnoreFile = content
			}
		}
	}

	for _, f := range cg.Cookbook.AllFiles {
		ignore, err := cg.ignoreThisFile(f.Name, false)
		if err != nil {
			return fmt.Errorf("Ignore check failed for file %s: %s", f.Path, err)
		}
		if ignore {
			continue
		}

		content, err := downloadCookbookFile(client, *cg.ChefOrgID, f.Checksum)
		if err != nil {
			return fmt.Errorf("Failed to dowload %s from the %s cookbook: %s", f.Path, cg.Cookbook.Name, err)
		}

		if err := writeFileToDisk(path.Join(cg.CookbookPath, f.Path), strings.NewReader(string(content))); err != nil {
			return fmt.Errorf("Failed to write file %s to disk: %s", path.Join(cg.CookbookPath, f.Path), err)
		}

		// Save the md5 hash to the ChefGuard struct
		cg.FileHashes[f.Path] = md5.Sum(content)

		// Add the file to the tar archive
		header := &tar.Header{
			Name:    fmt.Sprintf("%s/%s", cg.Cookbook.Name, f.Path),
			Size:    int64(len(content)),
			Mode:    0644,
			ModTime: time.Now(),
		}

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("Failed to create header for file %s: %s", f.Name, err)
		}

		if _, err := tw.Write(content); err != nil {
			return fmt.Errorf("Failed to write file %s to archive: %s", f.Name, err)
		}
	}

	if err := addMetadataJSON(tw, cg.Cookbook); err != nil {
		return fmt.Errorf("Failed to create metadata.json: %s", err)
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("Failed to close the tar archive: %s", err)
	}

	if err := gw.Close(); err != nil {
		return fmt.Errorf("Failed to close the gzip archive: %s", err)
	}

	cg.TarFile = buf.Bytes()
	return nil
}

// Sandbox represents a Chef sandbox used for uploading cookbook files
type Sandbox struct {
	SandboxID string                 `json:"sandbox_id"`
	URI       string                 `json:"uri"`
	Checksums map[string]SandboxItem `json:"checksums"`
}

// SandboxItem represenst a single sandbox item (e.g. a cookbook file)
type SandboxItem struct {
	URL         string `json:"url"`
	NeedsUpload bool   `json:"needs_upload"`
}

func (cg *ChefGuard) getOrganizationID() error {
	resp, err := cg.chefClient.Post(
		"sandboxes",
		"application/json",
		nil,
		strings.NewReader(`{"checksums":{"00000000000000000000000000000000":null}}`),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := checkHTTPResponse(resp, []int{http.StatusOK, http.StatusCreated}); err != nil {
		return err
	}
	sb := new(Sandbox)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Failed to get body from call to %s: %s", resp.Request.URL.String(), err)
	}
	if err := json.Unmarshal(body, &sb); err != nil {
		return err
	}
	re := regexp.MustCompile(`^.*/organization-(.*)\/checksum-.*$`)
	u := sb.Checksums["00000000000000000000000000000000"].URL
	if res := re.FindStringSubmatch(u); res != nil {
		cg.ChefOrgID = &res[1]
		return nil
	}
	return fmt.Errorf("Could not find an organization ID in reply: %s", string(body))
}

func (cg *ChefGuard) tagAndPublishCookbook() (int, error) {
	if !cg.SourceCookbook.artifact {
		tag := fmt.Sprintf("v%s", cg.Cookbook.Version)

		if !cg.SourceCookbook.tagged {
			mail := fmt.Sprintf("%s@%s", cg.User, getEffectiveConfig("MailDomain", cg.ChefOrg).(string))
			err := tagCookbook(cg.SourceCookbook.gitConfig, cg.Cookbook.Name, tag, cg.User, mail)
			if err != nil {
				return http.StatusBadRequest, err
			}
		}
		if getEffectiveConfig("PublishCookbook", cg.ChefOrg).(bool) && cg.SourceCookbook.private {
			if err := cg.publishCookbook(); err != nil {
				errText := err.Error()
				if !cg.SourceCookbook.tagged {
					err := untagCookbook(cg.SourceCookbook.gitConfig, cg.Cookbook.Name, tag)
					if err != nil {
						errText = fmt.Sprintf("%s - NOTE: Failed to untag the repo during cleanup!", errText)
					}
				}
				return http.StatusBadRequest, fmt.Errorf(errText)
			}
		}
	}
	return 0, nil
}

func (cg *ChefGuard) getCookbookChangeDetails(r *http.Request) []byte {
	v := mux.Vars(r)

	cg.ChangeDetails = &changeDetails{
		Item: fmt.Sprintf("%s-%s.json", v["name"], v["version"]),
		Type: v["type"],
	}

	frozen := false
	if cg.Cookbook != nil {
		frozen = cg.Cookbook.Frozen
	}

	source := "N/A"
	if cg.SourceCookbook != nil {
		source = cg.SourceCookbook.sourceURL
	}

	details := fmt.Sprintf(
		"{\"name\":\"%s\",\"version\":\"%s\",\"frozen\":%t,\"forcedupload\":%t,\"source\":\"%s\", \"uploaded\": \"%s\"}",
		v["name"],
		v["version"],
		frozen,
		cg.ForcedUpload,
		source,
		time.Now().Format("2006-01-02 15:04:05"),
	)

	return []byte(details)
}

func downloadCookbookFile(c *http.Client, orgID, checksum string) ([]byte, error) {
	var urlStr string

	if cfg.Chef.Type == "goiardi" {
		urlStr = fmt.Sprintf("%s/file_store/%s", getChefBaseURL(), checksum)
	} else {
		u, err := generateSignedURL(orgID, checksum)
		if err != nil {
			return nil, err
		}
		urlStr = u.String()
	}

	resp, err := c.Get(urlStr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := checkHTTPResponse(resp, []int{http.StatusOK}); err != nil {
		return nil, err
	}

	return ioutil.ReadAll(resp.Body)
}

// HMAC SHA256
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// Hash SHA256
func hashSHA256(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Create the signing key
func getSignatureKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

// Generate the canonical query string
func getCanonicalQueryString(params url.Values) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	queryString := make([]string, 0, len(params))
	for _, k := range keys {
		queryString = append(queryString, fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(params.Get(k))))
	}

	return strings.Join(queryString, "&")
}

// Get canonical headers and signed headers
func getCanonicalHeaders(headers map[string]string) (string, string) {
	var headerKeys []string
	for k := range headers {
		headerKeys = append(headerKeys, strings.ToLower(k))
	}
	sort.Strings(headerKeys)
	var canonicalHeaders, signedHeaders string
	for _, k := range headerKeys {
		canonicalHeaders += fmt.Sprintf("%s:%s\n", k, strings.TrimSpace(headers[k]))
		signedHeaders += fmt.Sprintf("%s;", k)
	}
	signedHeaders = strings.TrimSuffix(signedHeaders, ";")
	return canonicalHeaders, signedHeaders
}

// Generate the signed URL
func getSignedURL(accessKey, secretKey, region, service, method, uri string, queryParams map[string]string, headers map[string]string, payload string) string {
	algorithm := "AWS4-HMAC-SHA256"
	t := time.Now()
	date := t.Format("20060102")
	amzDate := t.Format("20060102T150405Z")
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", date, region, service)

	query := url.Values{}
	for k, v := range queryParams {
		query.Set(k, v)
	}
	query.Set("X-Amz-Algorithm", algorithm)
	query.Set("X-Amz-Credential", fmt.Sprintf("%s/%s", accessKey, credentialScope))
	query.Set("X-Amz-Date", amzDate)
	query.Set("X-Amz-Expires", "86400")
	query.Set("X-Amz-SignedHeaders", "host")

	canonicalURI := uri
	canonicalQueryString := getCanonicalQueryString(query)
	canonicalHeaders, signedHeaders := getCanonicalHeaders(headers)

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payload,
	)

	// GET
	// /bookshelf/organization-0751dc28b5a6978ca80465d54cc7f6ff/checksum-6d5e878f0b1e6b2c9e368a4e6234462b
	// X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=00efc6e783b514a4516a%2F20240717%2Fchef%2Fs3%2Faws4_request&X-Amz-Date=20240717T151227Z&X-Amz-Expires=86400
	// host:infra.chef.saas.acc.schubergphilis.com

	// host
	// UNSIGNED-PAYLOAD

	hashedCanonicalRequest := hashSHA256(canonicalRequest)
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		algorithm,
		amzDate,
		credentialScope,
		hashedCanonicalRequest,
	)

	// AWS4-HMAC-SHA256
	// 20240717T171604Z
	// 20240717/chef/s3/aws4_request
	// bca48d5c547f6d8b1412a648e9b47a445bdc8173aa6cfe5e61830e8142c1e283

	signingKey := getSignatureKey(secretKey, date, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	query.Set("X-Amz-Signature", signature)

	signedURL := fmt.Sprintf("https://%s%s?%s", headers["host"], uri, query.Encode())
	return signedURL
}

func generateSignedURL(orgID, checksum string) (*url.URL, error) {

	accessKey := cfg.Chef.BookshelfKey
	secretKey := cfg.Chef.BookshelfSecret
	region := cfg.Chef.BookshelfRegion
	service := "s3"
	method := "GET"
	uri := fmt.Sprintf("/%s/organization-%s/checksum-%s", cfg.Chef.BookshelfBucket, orgID, checksum)
	bookshelfDomain := cfg.Chef.BookshelfDomain

	queryParams := map[string]string{}

	headers := map[string]string{
		"host": bookshelfDomain,
	}

	signedURL := getSignedURL(accessKey, secretKey, region, service, method, uri, queryParams, headers, "UNSIGNED-PAYLOAD")

	// https://infra.chef.saas.acc.schubergphilis.com:443
	// /bookshelf/organization-0751dc28b5a6978ca80465d54cc7f6ff/checksum-5a64b525b6b148539060365ee4980839
	// ?X-Amz-Algorithm=AWS4-HMAC-SHA256
	// &X-Amz-Credential=00efc6e783b514a4516a%2F20240717%2Fchef%2Fs3%2Faws4_request
	// &X-Amz-Date=20240717T112134Z
	// &X-Amz-Expires=10800
	// &X-Amz-SignedHeaders=host
	// &X-Amz-Signature=10ee4d844d505fa7d7d96133634f93982ba9f3d9e939ffd632201a339ad6244a

	return url.Parse(signedURL)
}

func writeFileToDisk(filePath string, content io.Reader) error {
	if err := os.MkdirAll(path.Dir(filePath), 0755); err != nil {
		return err
	}
	fo, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer fo.Close()

	if _, err := io.Copy(fo, content); err != nil {
		return err
	}
	return nil
}

func addMetadataJSON(tw *tar.Writer, cb *CookbookVersion) error {
	for _, f := range cb.AllFiles {
		if f.Path == "metadata.json" {
			return nil
		}
	}
	md, err := json.MarshalIndent(cb.Metadata, "", "  ")
	if err != nil {
		return err
	}
	md = decodeMarshalledJSON(md)
	header := &tar.Header{
		Name:    fmt.Sprintf("%s/%s", cb.Name, "metadata.json"),
		Size:    int64(len(md)),
		Mode:    0644,
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	if _, err := tw.Write(md); err != nil {
		return err
	}
	return nil
}

// ErrorInfo is single type used for several different types of errors
type ErrorInfo struct {
	Error         []string `json:"error,omitempty"`
	Errors        []string `json:"errors,omitempty"`
	ErrorMessages []string `json:"error_messages,omitempty"`
}

func checkHTTPResponse(resp *http.Response, allowedStates []int) error {
	for _, s := range allowedStates {
		if resp.StatusCode == s {
			return nil
		}
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Failed to get body from call to %s: %s", resp.Request.URL.String(), err)
	}

	// Make sure we return an error, even if we have no error details
	if len(body) == 0 {
		return errors.New("No error details found")
	}

	// If this returns an error the return body is probably not JSON,
	// in which case we just move on and return the raw body instead.
	// Otherwise let's see if we parsed out some error details and
	// return those.
	errInfo := &ErrorInfo{}
	if err := json.Unmarshal(body, errInfo); err == nil {
		if errInfo.Error != nil {
			return fmt.Errorf(strings.Join(errInfo.Error, ";"))
		}
		if errInfo.Errors != nil {
			return fmt.Errorf(strings.Join(errInfo.Errors, ";"))
		}
		if errInfo.ErrorMessages != nil {
			return fmt.Errorf(strings.Join(errInfo.ErrorMessages, ";"))
		}
	}

	// If we could not marshal the body or we didn't parse any errors
	// just return the raw body.
	return fmt.Errorf(string(body))
}

func getChefBaseURL() string {
	var baseURL string
	switch cfg.Chef.Port {
	case "443":
		baseURL = "https://" + cfg.Chef.Server
	case "80":
		baseURL = "http://" + cfg.Chef.Server
	default:
		baseURL = "http://" + cfg.Chef.Server + ":" + cfg.Chef.Port
	}
	return baseURL
}

func dumpBody(r interface{}) (body []byte, err error) {
	switch r.(type) {
	case *http.Request:
		body, err = ioutil.ReadAll(r.(*http.Request).Body)
		r.(*http.Request).Body = ioutil.NopCloser(bytes.NewBuffer(body))
	case *http.Response:
		body, err = ioutil.ReadAll(r.(*http.Response).Body)
		r.(*http.Response).Body = ioutil.NopCloser(bytes.NewBuffer(body))
	}
	return body, err
}
