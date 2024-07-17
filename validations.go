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
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/xanzy/go-pathspec"
)

// SourceCookbook represents the details of the cookbook used as source
type SourceCookbook struct {
	artifact  bool
	private   bool
	tagged    bool
	gitConfig string
	sourceURL string

	File         string   `json:"file,omitempty"`
	DownloadURL  *url.URL `json:"url"`
	LocationType string   `json:"location_type"`
	LocationPath string   `json:"location_path,omitempty"`
}

// Constraints holds all known contraints for a given cookbook
type Constraints struct {
	CookbookVersions map[string]string   `json:"cookbook_versions"`
	ChefType         string              `json:"chef_type"`
	Environment      string              `json:"name"`
	RunList          []string            `json:"run_list"`
	EnvRunLists      map[string][]string `json:"env_run_lists"`
}

func unmarshalConstraints(body []byte) (*Constraints, error) {
	var c Constraints
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, err
	}
	for _, r := range c.EnvRunLists {
		c.RunList = append(c.RunList, r...)
	}
	return &c, nil
}

func (cg *ChefGuard) checkCookbookFrozen() (int, error) {
	frozen, err := cg.cookbookFrozen(cg.Cookbook.Name, cg.Cookbook.Version)
	if err != nil {
		return http.StatusBadRequest, err
	}
	if frozen {
		return http.StatusConflict, fmt.Errorf("\n=== Cookbook Upload error found ===\n" +
			"The cookbook you are trying to upload is frozen!\n" +
			"It is not allowed to overwrite a frozen cookbook,\n" +
			"so please bump the version and try again.\n" +
			"===================================\n")
	}
	return 0, nil
}

func (cg *ChefGuard) validateCookbookStatus() (int, error) {
	if cg.Cookbook.Metadata.Dependencies != nil {
		errCode, err := cg.checkDependencies(parseCookbookVersions(cg.Cookbook.Metadata.Dependencies), false)
		if err != nil {
			if errCode == http.StatusPreconditionFailed {
				err = fmt.Errorf("\n=== Dependency errors found ===\n"+
					"%s\n"+
					"=================================\n", err)
			}
			return errCode, err
		}
	}
	errCode, err := cg.searchSourceCookbook()
	if err != nil {
		if errCode == http.StatusPreconditionFailed {
			err = fmt.Errorf("\n=== Cookbook Compare errors found ===\n"+
				"%s\n"+
				"=====================================\n", err)
		}
		return errCode, err
	}
	if !cg.SourceCookbook.artifact {
		if errCode, err := cg.executeChecks(); err != nil {
			return errCode, err
		}
	}
	if errCode, err := cg.compareCookbooks(); err != nil {
		if errCode == http.StatusPreconditionFailed {
			switch cg.SourceCookbook.LocationType {
			case "supermarket":
				err = fmt.Errorf("\n=== Cookbook Compare errors found ===\n"+
					"%s\n\nSource: %s\n\n"+
					"Make sure you are using an unchanged community version\n"+
					"or, if you really need to change something, make a fork and\n"+
					"and create a pull request back to the community cookbook\n"+
					"before trying to upload the cookbook again.\n"+
					"=====================================\n", err, strings.Split(cg.SourceCookbook.DownloadURL.String(), "&")[0])
			case "git":
				err = fmt.Errorf("\n=== Cookbook Compare errors found ===\n"+
					"%s\n\nSource: %s\n\n"+
					"Make sure all your changes are merged into the central\n"+
					"repositories before trying to upload the cookbook again.\n\n"+
					"HINT: Also double check your line endings (CRLF vs LF)!\n"+
					"=====================================\n", err, strings.Split(cg.SourceCookbook.DownloadURL.String(), "&")[0])
			default:
				err = fmt.Errorf("\n=== Cookbook Compare errors found ===\n"+
					"%s\n\nSource: %s\n"+
					"=====================================\n", err, strings.Split(cg.SourceCookbook.DownloadURL.String(), "&")[0])
			}
		}
		return errCode, err
	}
	return 0, nil
}

func (cg *ChefGuard) validateConstraints(body []byte) (int, error) {
	c, err := unmarshalConstraints(body)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("Failed to unmarshal body %s: %s", string(body), err)
	}

	devEnv := getEffectiveConfig("DevEnvironment", cg.ChefOrg).(string)
	if c.CookbookVersions != nil && (c.ChefType == "environment" && c.Environment != devEnv) {
		errCode, err := cg.checkDependencies(parseCookbookVersions(c.CookbookVersions), true)
		if err != nil {
			if errCode == http.StatusPreconditionFailed {
				err = cg.formatConstraintsError(err)
			}
			return errCode, err
		}
	}
	if c.RunList != nil {
		if errCode, err := cg.checkDependencies(parseRunlists(c.RunList), true); err != nil {
			if errCode == http.StatusPreconditionFailed {
				err = cg.formatConstraintsError(err)
			}
			return errCode, err
		}
	}
	return 0, nil
}

func (cg *ChefGuard) formatConstraintsError(err error) error {
	if getEffectiveConfig("ValidateChanges", cg.ChefOrg).(string) == "permissive" {
		return fmt.Errorf("\n==== Cookbook Constraints errors found ====\n"+
			"RUNNNING PERMISSIVE MODE: CHANGES ARE SAVED\n"+
			"\n%s\n"+
			"===========================================\n", err)
	}
	return fmt.Errorf("\n=== Cookbook Constraints errors found ===\n"+
		"%s\n"+
		"=========================================\n", err)
}

func (cg *ChefGuard) checkDependencies(constraints map[string][]string, validateConstraints bool) (int, error) {
	errors := []string{}
	for name, versions := range constraints {
		for _, version := range versions {
			if version == "0.0.0" || version == "BAD>= 0.0.0" {
				continue
			}
			if strings.HasPrefix(version, "BAD") {
				if validateConstraints {
					errors = append(errors, fmt.Sprintf(
						"constraint '%s' for %s needs to be more specific (= x.x.x)", strings.TrimPrefix(version, "BAD"), name))
				}
				continue
			}
			frozen, err := cg.cookbookFrozen(name, version)
			if err != nil {
				return http.StatusBadRequest, err
			}
			if !frozen {
				errors = append(errors, fmt.Sprintf("%s version %s needs to be frozen", name, version))
			}
		}
	}
	if len(errors) > 0 {
		return http.StatusPreconditionFailed, fmt.Errorf(" - %s", strings.Join(errors, "\n - "))
	}
	return 0, nil
}

func (cg *ChefGuard) cookbookFrozen(name, version string) (bool, error) {
	cb, found, err := cg.chefClient.GetCookbookVersion(name, version)
	if err != nil {
		return true, fmt.Errorf("Failed to get info for cookbook %s version %s: %s", name, version, err)
	}
	if !found {
		return false, nil
	}
	return cb.Frozen, nil
}

func (cg *ChefGuard) compareCookbooks() (int, error) {
	sh, err := cg.getSourceFileHashes()
	if err != nil {
		return http.StatusBadRequest, err
	}
	changed := []string{}
	missing := []string{}
	for file, fHash := range cg.FileHashes {
		if file == "metadata.json" {
			delete(sh, file)
			continue
		}
		if sHash, exists := sh[file]; exists {

			// INFO.Printf("Checking file %s", file)
			// INFO.Printf("Comparing file %s", file)
			// INFO.Printf("Source hash: %x", sHash)
			// INFO.Printf("Upload hash: %x", fHash)

			if fHash == sHash {
				delete(sh, file)
			} else {
				changed = append(changed, file)
			}
		} else {
			ignore, err := cg.ignoreThisFile(file, true)
			if err != nil {
				return http.StatusBadRequest, err
			}
			if !ignore {
				missing = append(missing, file)
			}
		}
	}
	if len(changed) > 0 {
		sort.StringSlice(changed).Sort()
		return http.StatusPreconditionFailed, fmt.Errorf(
			"The following file(s) are changed:\n - %s", strings.Join(changed, "\n - "))
	}
	if len(missing) > 0 {
		sort.StringSlice(missing).Sort()
		return http.StatusPreconditionFailed, fmt.Errorf(
			"Your upload contains more files than the source cookbook:\n - %s", strings.Join(missing, "\n - "))
	}
	if len(sh) > 0 {
		for file := range sh {
			ignore, err := cg.ignoreThisFile(file, true)
			if err != nil {
				return http.StatusBadRequest, err
			}
			if !ignore {
				missing = append(missing, file)
			}
		}
		if len(missing) > 0 {
			sort.StringSlice(missing).Sort()
			return http.StatusPreconditionFailed, fmt.Errorf(
				"The source cookbook contains more files than your upload:\n - %s", strings.Join(missing, "\n - "))
		}
	}
	return 0, nil
}

func (cg *ChefGuard) searchSourceCookbook() (errCode int, err error) {
	cg.SourceCookbook, errCode, err = searchCommunityCookbooks(cg.Cookbook.Name, cg.Cookbook.Version)
	if err != nil {
		return errCode, err
	}
	if cg.SourceCookbook != nil {
		return 0, nil
	}
	cg.SourceCookbook, errCode, err = searchPrivateCookbooks(cg.ChefOrg, cg.Cookbook.Name, cg.Cookbook.Version)
	if err != nil {
		return errCode, err
	}
	if cg.SourceCookbook != nil {
		return 0, nil
	}
	return http.StatusPreconditionFailed, fmt.Errorf(
		"Failed to locate the source of the %s cookbook!", cg.Cookbook.Name)
}

func (cg *ChefGuard) ignoreThisFile(file string, ignoreDefaultFiles bool) (ignore bool, err error) {
	if ignoreDefaultFiles {
		INFO.Printf("Checking default ignore files for %s", file)
		if file == "metadata.rb" || file == "metadata.json" || strings.HasPrefix(file, "spec/") || strings.HasPrefix(file, "test/") {
			return true, nil
		}
	}
	ignore, err = pathspec.GitIgnore(bytes.NewReader(cg.GitIgnoreFile), file)
	if ignore || err != nil {
		return ignore, err
	}
	ignore, err = pathspec.ChefIgnore(bytes.NewReader(cg.ChefIgnoreFile), file)
	if ignore || err != nil {
		return ignore, err
	}
	return false, nil
}

func (cg *ChefGuard) getSourceFileHashes() (map[string][16]byte, error) {
	client, err := newDownloadClient(cg.SourceCookbook)
	if err != nil {
		return nil, fmt.Errorf("Failed to create a new download client: %s", err)
	}

	resp, err := client.Get(cg.SourceCookbook.DownloadURL.String())
	if err != nil {
		return nil, fmt.Errorf(
			"Failed to download the cookbook from %s: %s", strings.Split(cg.SourceCookbook.DownloadURL.String(), "&")[0], err)
	}
	defer resp.Body.Close()

	if err := checkHTTPResponse(resp, []int{http.StatusOK}); err != nil {
		return nil, fmt.Errorf(
			"Failed to download the cookbook from %s: %s", strings.Split(cg.SourceCookbook.DownloadURL.String(), "&")[0], err)
	}

	var tr *tar.Reader
	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to create a new gzipReader: %s", err)
	}

	tr = tar.NewReader(gr)
	files := make(map[string][16]byte)
	for {
		header, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("Failed to process all files: %s", err)
		}
		if header == nil {
			break
		}

		if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
			content, err := ioutil.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("Failed to process all files: %s", err)
			}

			file := strings.SplitN(header.Name, "/", 2)[1]

			// The source version should be leading, so save .gitignore file if we find one
			if file == ".gitignore" {
				cg.GitIgnoreFile = content
			}

			// The source version should be leading, so save chefignore file if we find one
			if file == "chefignore" {
				cg.ChefIgnoreFile = content
			}

			files[file] = md5.Sum(content)
		}
	}

	return files, nil
}

func searchCommunityCookbooks(name, version string) (*SourceCookbook, int, error) {
	sc, errCode, err := searchSupermarket(cfg.Community.Supermarket, name, version)
	if err != nil {
		return nil, errCode, err
	}
	if sc != nil {
		sc.private = false
		return sc, 0, nil
	}
	if errCode == 1 {
		if cfg.Community.Forks != "" {
			sc, err = searchGit(strings.Split(cfg.Community.Forks, ","), name, version, true)
			if err != nil {
				return nil, http.StatusBadRequest, err
			}
			if sc != nil {
				// Do additional tests to check for a PR!
				sc.private = false
				return sc, 0, nil
			}
		}
		return nil, http.StatusPreconditionFailed, fmt.Errorf(
			"You are trying to upload '%s' version '%s' which is a\n"+
				"non-existing version of a community cookbook! Make sure you are using\n"+
				"an existing community version, or a fork with a pending pull request.", name, version)
	}
	return nil, 0, nil
}

func searchPrivateCookbooks(chefOrg, name, version string) (*SourceCookbook, int, error) {
	if cfg.Supermarket.Server != "" {
		var u string
		switch cfg.Supermarket.Port {
		case "80":
			u = fmt.Sprintf("http://%s", cfg.Supermarket.Server)
		case "443":
			u = fmt.Sprintf("https://%s", cfg.Supermarket.Server)
		default:
			u = fmt.Sprintf("http://%s:%s", cfg.Supermarket.Server, cfg.Supermarket.Port)
		}
		sc, errCode, err := searchSupermarket(u, name, version)
		if err != nil {
			return nil, errCode, err
		}
		if sc != nil {
			sc.private = true
			return sc, 0, nil
		}
	}
	if getEffectiveConfig("SearchGit", chefOrg).(bool) {
		gitConfigs := cfg.Default.GitCookbookConfigs
		custGitConfigs := getEffectiveConfig("GitCookbookConfigs", chefOrg)
		if gitConfigs != custGitConfigs {
			gitConfigs = fmt.Sprintf("%s,%s", gitConfigs, custGitConfigs)
		}
		sc, err := searchGit(strings.Split(gitConfigs, ","), name, version, false)
		if err != nil {
			return nil, http.StatusBadRequest, err
		}
		if sc != nil {
			sc.private = true
			return sc, 0, nil
		}
	}
	return nil, 0, nil
}

func searchSupermarket(supermarket, name, version string) (*SourceCookbook, int, error) {
	u, err := url.Parse(fmt.Sprintf("%s/%s", supermarket, "universe"))
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf(
			"Failed to parse the community cookbooks URL %s: %s", supermarket, err)
	}
	resp, err := http.Get(u.String())
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf(
			"Failed to get cookbook list from %s: %s", u.String(), err)
	}
	defer resp.Body.Close()
	if err := checkHTTPResponse(resp, []int{http.StatusOK}); err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf(
			"Failed to get cookbook list from %s: %s", u.String(), err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf(
			"Failed to read the response body from %v: %s", resp, err)
	}
	results := make(map[string]map[string]*SourceCookbook)
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf(
			"Failed to unmarshal body %s: %s", string(body), err)
	}
	if cb, exists := results[name]; exists {
		if sc, exists := cb[version]; exists {
			sc.artifact = true
			u, err := communityDownloadURL(sc.LocationPath, name, version)
			if err != nil {
				return nil, http.StatusBadRequest, err
			}
			sc.DownloadURL = u
			sc.sourceURL = strings.Split(u.String(), "&")[0]
			return sc, 0, nil
		}

		// Return error code 1 if the we can find the cookbook, but not the correct version
		return nil, 1, nil
	}
	return nil, 0, nil
}

func communityDownloadURL(path, name, version string) (*url.URL, error) {
	u, err := url.Parse(fmt.Sprintf(
		"%s/cookbooks/%s/versions/%s", path, name, strings.Replace(version, ".", "_", -1)))
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the cookbook URL %s: %s", fmt.Sprintf("%s/cookbooks/%s/versions/%s",
			path, name, strings.Replace(version, ".", "_", -1)), err)
	}
	resp, err := http.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("Failed to get cookbook info from %s: %s", u.String(), err)
	}
	defer resp.Body.Close()
	if err := checkHTTPResponse(resp, []int{http.StatusOK}); err != nil {
		return nil, fmt.Errorf("Failed to get cookbook info from %s: %s", u.String(), err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to read the response body from %v: %s", resp, err)
	}
	sc := &SourceCookbook{}
	if err := json.Unmarshal(body, &sc); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal body %s: %s", string(body), err)
	}
	u, err = url.Parse(sc.File)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the cookbook download URL %s: %s", sc.File, err)
	}
	return u, nil
}

func searchGit(gitConfigs []string, name, version string, tagsOnly bool) (*SourceCookbook, error) {
	for _, gitConfig := range gitConfigs {
		gitConfig = strings.TrimSpace(gitConfig)
		link, tagged, err := searchGitForCookbook(gitConfig, name, fmt.Sprintf("v%s", version), tagsOnly)
		if err != nil {
			return nil, err
		}
		if link != nil {
			sc := &SourceCookbook{LocationType: "git"}
			sc.artifact = false
			sc.tagged = tagged
			sc.gitConfig = gitConfig
			sc.DownloadURL = link
			sc.sourceURL = strings.Split(link.String(), "&")[0]
			return sc, nil
		}
	}
	return nil, nil
}

func newDownloadClient(sc *SourceCookbook) (*http.Client, error) {
	if sc.LocationType != "git" {
		return http.DefaultClient, nil
	}
	if _, ok := cfg.Git[sc.gitConfig]; !ok {
		return nil, fmt.Errorf("No Git config specified for: %s!", sc.gitConfig)
	}

	client := http.DefaultClient

	if gitConfig, ok := cfg.Git[sc.gitConfig]; ok && gitConfig.SSLNoVerify {
		client = &http.Client{Transport: insecureTransport}
	}

	return client, nil
}

func parseCookbookVersions(constraints map[string]string) map[string][]string {
	re := regexp.MustCompile(`^(?:= )?(\d+\.\d+\.\d+)$`)
	cbs := make(map[string][]string)
	for name, constraint := range constraints {
		if res := re.FindStringSubmatch(constraint); res != nil {
			version := res[1]
			cbs[name] = []string{version}
		} else {
			cbs[name] = []string{"BAD" + constraint}
		}
	}
	return cbs
}

func parseRunlists(runlists []string) map[string][]string {
	re := regexp.MustCompile(`^.*\[(\w+).*@(\d+\.\d+\.\d+)\]$`)
	cbs := make(map[string][]string)
	for _, constraint := range runlists {
		if res := re.FindStringSubmatch(constraint); res != nil {
			name := res[1]
			version := res[2]
			if !contains(cbs[name], version) {
				cbs[name] = append(cbs[name], version)
			}
		}
	}
	return cbs
}

func contains(versions []string, version string) bool {
	for _, v := range versions {
		if v == version {
			return true
		}
	}
	return false
}
