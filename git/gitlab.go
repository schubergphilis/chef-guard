//
// Copyright 2015, Sander van Harmelen
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

package git

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xanzy/go-gitlab"
)

const (
	invalidGitLabToken = "The token configured for GitLab group %s is not valid!"
)

// GetContent implements the Git interface
func (g *GitLab) GetContent(project, path string) (*File, interface{}, error) {
	ns := fmt.Sprintf("%s/%s", g.group, project)

	fileOpts := &gitlab.GetFileOptions{
		Ref: gitlab.String("master"),
	}
	file, resp, err := g.client.RepositoryFiles.GetFile(ns, path, fileOpts)
	if err != nil {
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusNotFound:
				return nil, nil, nil
			case http.StatusUnauthorized:
				return nil, nil, fmt.Errorf(invalidGitLabToken, g.group)
			}
		}
		return nil, nil, fmt.Errorf("Error retrieving file %s: %v", path, err)
	}

	f := &File{
		Content: file.Content,
		SHA:     file.CommitID,
	}

	if file.Encoding == "base64" {
		content, err := base64.StdEncoding.DecodeString(file.Content)
		if err != nil {
			return nil, nil, fmt.Errorf("Error decoding file %s, %v", path, err)
		}

		f.Content = string(content)
	}

	return f, nil, nil
}

// CreateFile implements the Git interface
func (g *GitLab) CreateFile(project, path, msg string, usr *User, content []byte) (string, error) {
	ns := fmt.Sprintf("%s/%s", g.group, project)

	opts := &gitlab.CreateFileOptions{
		Branch:        gitlab.String("master"),
		AuthorEmail:   &usr.Mail,
		AuthorName:    &usr.Name,
		Content:       gitlab.String(string(content)),
		CommitMessage: gitlab.String(msg),
	}
	_, resp, err := g.client.RepositoryFiles.CreateFile(ns, path, opts)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return "", fmt.Errorf(invalidGitLabToken, g.group)
		}
		return "", fmt.Errorf("Error creating file %s: %v", path, err)
	}

	return g.shaOfLatestCommit(project)
}

// UpdateFile implements the Git interface
func (g *GitLab) UpdateFile(project, path, sha, msg string, usr *User, content []byte) (string, error) {
	ns := fmt.Sprintf("%s/%s", g.group, project)

	opts := &gitlab.UpdateFileOptions{
		Branch:        gitlab.String("master"),
		AuthorEmail:   &usr.Mail,
		AuthorName:    &usr.Name,
		Content:       gitlab.String(string(content)),
		CommitMessage: gitlab.String(msg),
	}
	_, resp, err := g.client.RepositoryFiles.UpdateFile(ns, path, opts)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return "", fmt.Errorf(invalidGitLabToken, g.group)
		}
		return "", fmt.Errorf("Error updating file %s: %v", path, err)
	}

	return g.shaOfLatestCommit(project)
}

// DeleteFile implements the Git interface
func (g *GitLab) DeleteFile(project, path, sha, msg string, usr *User) (string, error) {
	ns := fmt.Sprintf("%s/%s", g.group, project)

	opts := &gitlab.DeleteFileOptions{
		Branch:        gitlab.String("master"),
		AuthorEmail:   &usr.Mail,
		AuthorName:    &usr.Name,
		CommitMessage: gitlab.String(msg),
	}
	resp, err := g.client.RepositoryFiles.DeleteFile(ns, path, opts)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return "", fmt.Errorf(invalidGitLabToken, g.group)
		}
		return "", fmt.Errorf("Error deleting file %s: %v", path, err)
	}

	return g.shaOfLatestCommit(project)
}

// DeleteDirectory implements the Git interface
func (g *GitLab) DeleteDirectory(project, msg string, dir interface{}, usr *User) error {
	ns := fmt.Sprintf("%s/%s", g.group, project)

	for _, file := range dir.([]string) {
		// Need a special case for when deleting data bag items
		fn := strings.TrimPrefix(file, "data_bags/")
		msg := fmt.Sprintf(msg, strings.TrimSuffix(fn, ".json"))

		opts := &gitlab.DeleteFileOptions{
			Branch:        gitlab.String("master"),
			AuthorEmail:   &usr.Mail,
			AuthorName:    &usr.Name,
			CommitMessage: gitlab.String(msg),
		}
		resp, err := g.client.RepositoryFiles.DeleteFile(ns, file, opts)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusUnauthorized {
				return fmt.Errorf(invalidGitLabToken, g.group)
			}
			return fmt.Errorf("Error deleting file %s: %v", file, err)
		}
	}

	return nil
}

// GetDiff implements the Git interface
func (g *GitLab) GetDiff(project, user, sha string) (string, error) {
	u := fmt.Sprintf("/%s/%s/commit/%s.diff", g.group, project, sha)

	req, err := g.client.NewRequest("GET", u, nil, nil)
	if err != nil {
		return "", err
	}

	// Make sure we do not use the API path here!
	req.URL, err = req.URL.Parse(u)
	if err != nil {
		return "", err
	}

	var diff bytes.Buffer
	resp, err := g.client.Do(req, &diff)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return "", fmt.Errorf(invalidGitLabToken, g.group)
		}
		return "", fmt.Errorf("Error retrieving commit %s: %v", sha, err)
	}

	if diff.Len() == 0 {
		return "", nil
	}

	const layout = "Mon Jan 2 3:04 2006"
	t := time.Now()

	msg := fmt.Sprintf("Commit : %s\nDate   : %s\nUser   : %s\n<br />%s",
		sha,
		t.Format(layout),
		user,
		diff.String(),
	)

	return msg, nil
}

// GetArchiveLink implements the Git interface
func (g *GitLab) GetArchiveLink(project, tag string) (*url.URL, error) {
	ns := fmt.Sprintf("%s/%s", g.group, project)

	_, resp, err := g.client.Projects.GetProject(ns, nil)
	if err != nil {
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusNotFound:
				return nil, nil
			case http.StatusUnauthorized:
				return nil, fmt.Errorf(invalidGitLabToken, g.group)
			}
		}
		return nil, fmt.Errorf("Error retrieving archive link of project %s: %v", project, err)
	}

	u, err := url.Parse(
		fmt.Sprintf("projects/%s/repository/archive.tar.gz?sha=%s&private_token=%s",
			url.QueryEscape(ns),
			tag,
			g.token,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse archive link: %v", err)
	}

	return g.client.BaseURL().ResolveReference(u), nil
}

// TagRepo implements the Git interface
func (g *GitLab) TagRepo(project, tag string, usr *User) error {
	ns := fmt.Sprintf("%s/%s", g.group, project)
	message := fmt.Sprint("Tagged by Chef-Guard\n")

	opts := &gitlab.CreateTagOptions{
		TagName: gitlab.String(tag),
		Ref:     gitlab.String("master"),
		Message: gitlab.String(message),
	}
	_, resp, err := g.client.Tags.CreateTag(ns, opts)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf(invalidGitLabToken, g.group)
		}
		return fmt.Errorf("Error creating tag for project %s: %v", project, err)
	}

	return nil
}

// TagExists implements the Git interface
func (g *GitLab) TagExists(project, tag string) (bool, error) {
	ns := fmt.Sprintf("%s/%s", g.group, project)

	_, resp, err := g.client.Tags.GetTag(ns, tag)
	if err != nil {
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusNotFound:
				return false, nil
			case http.StatusUnauthorized:
				return false, fmt.Errorf(invalidGitLabToken, g.group)
			}
		}
		return false, fmt.Errorf("Error retrieving tags of project %s: %v", project, err)
	}

	return true, nil
}

// UntagRepo implements the Git interface
func (g *GitLab) UntagRepo(project, tag string) error {
	ns := fmt.Sprintf("%s/%s", g.group, project)

	resp, err := g.client.Tags.DeleteTag(ns, tag)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf(invalidGitLabToken, g.group)
		}
		return fmt.Errorf("Error deleting tag %s: %v", tag, err)
	}

	return nil
}

func (g *GitLab) shaOfLatestCommit(project string) (string, error) {
	ns := fmt.Sprintf("%s/%s", g.group, project)

	commit, resp, err := g.client.Commits.GetCommit(ns, "master")
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return "", fmt.Errorf(invalidGitLabToken, g.group)
		}
		return "", fmt.Errorf("Error retrieving SHA of latest commit: %v", err)
	}

	return commit.ID, nil
}
