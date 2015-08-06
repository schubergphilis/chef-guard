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
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-github/github"
)

const (
	invalidGitHubToken = "The token configured for GitHub organization %s is not valid!"
)

// GetContent implements the Git interface
func (g *GitHub) GetContent(org, repo, path string) (*File, interface{}, error) {
	file, dir, resp, err := g.client.Repositories.GetContents(org, repo, path, nil)
	if err != nil {
		switch resp.StatusCode {
		case http.StatusNotFound:
			return nil, nil, nil
		case http.StatusUnauthorized:
			return nil, nil, fmt.Errorf(invalidGitHubToken, org)
		default:
			return nil, nil, fmt.Errorf("Error retrieving file %s: %v", path, err)
		}
	}

	if dir != nil {
		return nil, dir, nil
	}

	conf, err := file.Decode()
	if err != nil {
		return nil, nil, fmt.Errorf("Error decoding file %s: %v", path, err)
	}

	f := &File{
		Content: string(conf),
		SHA:     *file.SHA,
	}

	return f, nil, nil
}

// CreateFile implements the Git interface
func (g *GitHub) CreateFile(org, repo, path, msg string, usr *User, content []byte) (string, error) {
	opts := &github.RepositoryContentFileOptions{}
	opts.Committer = &github.CommitAuthor{Name: &usr.Name, Email: &usr.Mail}
	opts.Content = content
	opts.Message = &msg

	r, resp, err := g.client.Repositories.CreateFile(org, repo, path, opts)
	if err != nil {
		if resp.StatusCode == http.StatusUnauthorized {
			return "", fmt.Errorf(invalidGitHubToken, org)
		}
		return "", fmt.Errorf("Error creating file %s: %v", path, err)
	}

	return *r.SHA, nil
}

// UpdateFile implements the Git interface
func (g *GitHub) UpdateFile(org, repo, path, sha, msg string, usr *User, content []byte) (string, error) {
	opts := &github.RepositoryContentFileOptions{}
	opts.Committer = &github.CommitAuthor{Name: &usr.Name, Email: &usr.Mail}
	opts.Content = content
	opts.Message = &msg
	opts.SHA = &sha

	r, resp, err := g.client.Repositories.UpdateFile(org, repo, path, opts)
	if err != nil {
		if resp.StatusCode == http.StatusUnauthorized {
			return "", fmt.Errorf(invalidGitHubToken, org)
		}
		return "", fmt.Errorf("Error updating file %s: %v", path, err)
	}

	return *r.SHA, nil
}

// DeleteFile implements the Git interface
func (g *GitHub) DeleteFile(org, repo, path, sha, msg string, usr *User) (string, error) {
	opts := &github.RepositoryContentFileOptions{}
	opts.Committer = &github.CommitAuthor{Name: &usr.Name, Email: &usr.Mail}
	opts.Message = &msg
	opts.SHA = &sha

	r, resp, err := g.client.Repositories.DeleteFile(org, repo, path, opts)
	if err != nil {
		if resp.StatusCode == http.StatusUnauthorized {
			return "", fmt.Errorf(invalidGitHubToken, org)
		}
		return "", fmt.Errorf("Error deleting file %s: %v", path, err)
	}

	return *r.SHA, nil
}

// DeleteDirectory implements the Git interface
func (g *GitHub) DeleteDirectory(org, repo, msg string, dir interface{}, usr *User) error {
	opts := &github.RepositoryContentFileOptions{}
	opts.Committer = &github.CommitAuthor{Name: &usr.Name, Email: &usr.Mail}

	for _, file := range dir.([]*github.RepositoryContent) {
		// Need a special case for when deleting data bag items
		fn := strings.TrimPrefix(*file.Path, "data_bags/")
		msg := fmt.Sprintf(msg, strings.TrimSuffix(fn, ".json"))

		opts.Message = &msg
		opts.SHA = file.SHA

		_, resp, err := g.client.Repositories.DeleteFile(org, repo, *file.Path, opts)
		if err != nil {
			if resp.StatusCode == http.StatusUnauthorized {
				return fmt.Errorf(invalidGitHubToken, org)
			}
			return fmt.Errorf("Error deleting file %s: %v", *file.Path, err)
		}
	}

	return nil
}

// GetDiff implements the Git interface
func (g *GitHub) GetDiff(org, repo, user, sha string) (string, error) {
	commit, resp, err := g.client.Repositories.GetCommit(org, repo, sha)
	if err != nil {
		if resp.StatusCode == http.StatusUnauthorized {
			return "", fmt.Errorf(invalidGitHubToken, org)
		}
		return "", fmt.Errorf("Error retrieving commit %s: %v", sha, err)
	}

	if len(commit.Files) == 0 {
		return "", nil
	}

	const layout = "Mon Jan 2 3:04 2006"
	t := time.Now()
	msg := []string{fmt.Sprintf("Commit : %s\nDate   : %s\nUser   : %s",
		sha,
		t.Format(layout),
		user,
	)}

	for _, file := range commit.Files {
		patch := fmt.Sprintf("<br />\nFile: %s\n%s\n", *file.Filename, *file.Patch)
		msg = append(msg, patch)
	}

	return strings.Join(msg, "\n"), nil
}

// GetArchiveLink implements the Git interface
func (g *GitHub) GetArchiveLink(org, repo, tag string) (*url.URL, error) {
	link, resp, err := g.client.Repositories.GetArchiveLink(
		org, repo, github.Tarball, &github.RepositoryContentGetOptions{Ref: tag})
	if err != nil {
		switch resp.StatusCode {
		case http.StatusNotFound:
			return nil, nil
		case http.StatusUnauthorized:
			return nil, fmt.Errorf(invalidGitHubToken, org)
		default:
			return nil, fmt.Errorf("Error retrieving archive link of repo %s: %v", repo, err)
		}
	}

	return link, nil
}

// TagRepo implements the Git interface
func (g *GitHub) TagRepo(org, repo, tag string, usr *User) error {
	master, resp, err := g.client.Git.GetRef(org, repo, "heads/master")
	if err != nil {
		if resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf(invalidGitHubToken, org)
		}
		return fmt.Errorf("Error retrieving tags of repo %s: %v", repo, err)
	}

	message := fmt.Sprint("Tagged by Chef-Guard\n")
	ghTag := &github.Tag{Tag: &tag, Message: &message, Object: master.Object}
	ghTag.Tagger = &github.CommitAuthor{Name: &usr.Name, Email: &usr.Mail}

	tagObject, resp, err := g.client.Git.CreateTag(org, repo, ghTag)
	if err != nil {
		if resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf(invalidGitHubToken, org)
		}
		return fmt.Errorf("Error creating tag for repo %s: %v", repo, err)
	}

	refTag := fmt.Sprintf("tags/%s", tag)
	ref := &github.Reference{
		Ref:    &refTag,
		URL:    tagObject.URL,
		Object: &github.GitObject{SHA: tagObject.SHA},
	}
	if _, resp, err = g.client.Git.CreateRef(org, repo, ref); err != nil {
		return fmt.Errorf("Error creating tag for repo %s: %v", repo, err)
	}

	return nil
}

// TagExists implements the Git interface
func (g *GitHub) TagExists(org, repo, tag string) (bool, error) {
	ref := fmt.Sprintf("tags/%s", tag)

	_, resp, err := g.client.Git.GetRef(org, repo, ref)
	if err != nil {
		switch resp.StatusCode {
		case http.StatusNotFound:
			return false, nil
		case http.StatusUnauthorized:
			return false, fmt.Errorf(invalidGitHubToken, org)
		default:
			return false, fmt.Errorf("Error retrieving tags of repo %s: %v", repo, err)
		}
	}

	return true, nil
}

// UntagRepo implements the Git interface
func (g *GitHub) UntagRepo(org, repo, tag string) error {
	ref := fmt.Sprintf("tags/%s", tag)

	resp, err := g.client.Git.DeleteRef(org, repo, ref)
	if err != nil {
		if resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf(invalidGitHubToken, org)
		}
		return fmt.Errorf("Error deleting tag %s: %v", tag, err)
	}
	return nil
}