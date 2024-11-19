//
// Copyright 2024, Tom Snuverink
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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS V4 signed URL (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html)
func generateAWSV4SignedURL(orgID, checksum string) (*url.URL, error) {
	service := "s3"
	method := "GET"
	uri := fmt.Sprintf("/%s/organization-%s/checksum-%s", cfg.Chef.BookshelfBucket, orgID, checksum)

	queryParams := map[string]string{}
	headers := map[string]string{
		"host": cfg.Chef.BookshelfDomain,
	}

	signedURL := getSignedURL(cfg.Chef.BookshelfKey, cfg.Chef.BookshelfSecret, cfg.Chef.BookshelfRegion, service, method, uri, queryParams, headers, "UNSIGNED-PAYLOAD")

	return url.Parse(signedURL)
}

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

	hashedCanonicalRequest := hashSHA256(canonicalRequest)
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		algorithm,
		amzDate,
		credentialScope,
		hashedCanonicalRequest,
	)

	signingKey := getSignatureKey(secretKey, date, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	query.Set("X-Amz-Signature", signature)

	signedURL := fmt.Sprintf("https://%s%s?%s", headers["host"], uri, query.Encode())
	return signedURL
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hashSHA256(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func getSignatureKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

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
