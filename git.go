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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/xanzy/chef-guard/git"
	"github.com/xanzy/multisyncer"
)

var ms multisyncer.MultiSyncer

func (cg *ChefGuard) syncedGitUpdate(action string, body []byte) {
	if ms == nil {
		ms = multisyncer.New()
	}

	ms.Lock(cg.Repo)
	defer ms.Unlock(cg.Repo)

	// Once we get the lock, we wait for 500ms to prevent DDOS'ing the Git backend.
	time.Sleep(1 * time.Second)

	config, err := remarshalConfig(action, body)
	if err != nil {
		ERROR.Printf("Failed to convert %s config for %s %s for %s: %s",
			strings.TrimSuffix(cg.ChangeDetails.Type, "s"),
			strings.TrimSuffix(cg.ChangeDetails.Type, "s"),
			strings.TrimSuffix(cg.ChangeDetails.Item, ".json"),
			cg.User,
			err,
		)
		return
	}

	sha, err := cg.writeConfigToGit(action, config)
	if err != nil {
		ERROR.Printf("Failed to update %s %s for %s in git: %s",
			strings.TrimSuffix(cg.ChangeDetails.Type, "s"),
			strings.TrimSuffix(cg.ChangeDetails.Item, ".json"),
			cg.User,
			err,
		)
		return
	}

	if sha != "" {
		err := cg.mailChanges(
			fmt.Sprintf("%s/%s", cg.ChangeDetails.Type, cg.ChangeDetails.Item), sha, action)
		if err != nil {
			ERROR.Printf("Failed to send git spam: %s", err)
		}
	}
}

func (cg *ChefGuard) writeConfigToGit(action string, config []byte) (string, error) {
	var err error
	if cg.gitClient == nil {
		gitConfig, ok := cfg.Git[cfg.Default.GitConfig]
		if !ok {
			return "", fmt.Errorf("No Git config specified for: %s!", cfg.Default.GitConfig)
		}

		if cg.gitClient, err = git.NewGitClient(gitConfig); err != nil {
			return "", fmt.Errorf("Failed to create Git client: %s", err)
		}
	}

	msg := fmt.Sprintf("Config for %s %s %%s by Chef-Guard",
		strings.TrimSuffix(cg.ChangeDetails.Type, "s"),
		strings.TrimSuffix(cg.ChangeDetails.Item, ".json"),
	)
	user := &git.User{
		Name: cg.User,
		Mail: fmt.Sprintf("%s@%s", cg.User, getEffectiveConfig("MailDomain", cg.ChefOrg).(string)),
	}

	path := fmt.Sprintf("%s/%s", cg.ChangeDetails.Type, cg.ChangeDetails.Item)
	file, dir, err := cg.gitClient.GetContent(cg.Repo, path)
	if err != nil {
		return "", err
	}

	if file == nil && dir == nil {
		if action == "DELETE" {
			return "", fmt.Errorf("Failed to delete non-existing file or directory %s", path)
		}

		msg = fmt.Sprintf(msg, "created")
		return cg.gitClient.CreateFile(cg.Repo, path, msg, user, config)
	}

	if file != nil {
		if action == "DELETE" {
			msg = fmt.Sprintf(msg, "deleted")
			return cg.gitClient.DeleteFile(cg.Repo, path, file.SHA, msg, user)
		}

		if file.Content == string(config) {
			return "", nil
		}

		msg = fmt.Sprintf(msg, "updated")
		return cg.gitClient.UpdateFile(cg.Repo, path, file.SHA, msg, user, config)
	}

	return "", fmt.Errorf("Unknown error while updating file or directory content of %s", path)
}

func (cg *ChefGuard) mailChanges(file, sha, action string) error {
	if getEffectiveConfig("MailChanges", cg.ChefOrg).(bool) == false {
		return nil
	}

	diff, err := cg.getDiff(sha)
	if err != nil {
		return err
	}

	var subject string
	switch action {
	case "POST":
		subject = fmt.Sprintf("[%s CHEF] created %s", strings.ToUpper(cg.ChefOrg), file)
	case "PUT":
		subject = fmt.Sprintf("[%s CHEF] updated %s", strings.ToUpper(cg.ChefOrg), file)
	case "DELETE":
		subject = fmt.Sprintf("[%s CHEF] deleted %s", strings.ToUpper(cg.ChefOrg), file)
	}

	msg := createMessage(cg.Repo, cg.User, diff, subject)
	mail := getEffectiveConfig("MailSendBy", cg.ChefOrg).(string)
	if mail == "" {
		mail = fmt.Sprintf("%s@%s", cg.User, getEffectiveConfig("MailDomain", cg.ChefOrg).(string))
	}

	return mailDiff(cg.Repo, mail, msg)
}

func (cg *ChefGuard) getDiff(sha string) (string, error) {
	var err error
	if cg.gitClient == nil {
		gitConfig, ok := cfg.Git[cfg.Default.GitConfig]
		if !ok {
			return "", fmt.Errorf("No Git config specified for: %s!", cfg.Default.GitConfig)
		}

		if cg.gitClient, err = git.NewGitClient(gitConfig); err != nil {
			return "", fmt.Errorf("Failed to create Git client: %s", err)
		}
	}

	return cg.gitClient.GetDiff(cg.Repo, cg.User, sha)
}

func createMessage(org, user, diff, subject string) string {
	start := fmt.Sprintf(`From: %s
To: %s
Subject: %s
MIME-version: 1.0
Content-Type: text/html; charset="UTF-8"
<html>
<head>
<style><!--
  body {background-color:#ffffff;}
  .patch {margin:0;}
  #added {background-color:#ddffdd;}
  #removed {background-color:#ffdddd;}
  #context {background-color:#eeeeee;}
--></style>
</head>
<body>`, user, getEffectiveConfig("MailRecipient", org).(string), subject)

	end := fmt.Sprint(`</body>
</html>`)

	html := []string{start}
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "+"):
			line = fmt.Sprintf(`<pre class="patch" id="added">%s</pre>`, line)
		case strings.HasPrefix(line, "-"):
			line = fmt.Sprintf(`<pre class="patch" id="removed">%s</pre>`, line)
		default:
			line = fmt.Sprintf(`<pre class="patch" id="context">%s</pre>`, line)
		}
		html = append(html, line)
	}
	html = append(html, end)
	return strings.Join(html, "\n")
}

func mailDiff(org, from, msg string) error {
	host := getEffectiveConfig("MailServer", org).(string)
	port := getEffectiveConfig("MailPort", org).(int)

	c, err := smtp.Dial(fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}
	defer c.Close()
	if err = c.Hello(cfg.Chef.Server); err != nil {
		return err
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		config := &tls.Config{InsecureSkipVerify: true}
		if err = c.StartTLS(config); err != nil {
			return err
		}
	}
	if err = c.Mail(from); err != nil {
		return err
	}
	if err = c.Rcpt(getEffectiveConfig("MailRecipient", org).(string)); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(msg))
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}
	return c.Quit()
}

func searchGitForCookbook(gitConfig, repo, tag string, taggedOnly bool) (*url.URL, bool, error) {
	gitClient, err := getCustomClient(gitConfig)
	if err != nil {
		return nil, false, fmt.Errorf("Failed to create custom Git client: %s", err)
	}

	// First check if a tag exists
	tagged, err := gitClient.TagExists(repo, tag)
	if err != nil {
		return nil, false, err
	}

	if taggedOnly && !tagged {
		return nil, tagged, nil
	}

	if !tagged {
		tag = "master"
	}

	// Get the archive link for the tagged version or master
	link, err := gitClient.GetArchiveLink(repo, tag)
	if err != nil {
		return nil, tagged, err
	}

	return link, tagged, nil
}

func tagCookbook(gitConfig, cookbook, tag, user, mail string) error {
	gitClient, err := getCustomClient(gitConfig)
	if err != nil {
		return fmt.Errorf("Failed to create custom Git client: %s", err)
	}

	exists, err := gitClient.TagExists(cookbook, tag)
	if exists || err != nil {
		return err
	}

	usr := &git.User{
		Name: user,
		Mail: mail,
	}

	return gitClient.TagRepo(cookbook, tag, usr)
}

func untagCookbook(gitConfig, cookbook, tag string) error {
	gitClient, err := getCustomClient(gitConfig)
	if err != nil {
		return fmt.Errorf("Failed to create custom Git client: %s", err)
	}

	return gitClient.UntagRepo(cookbook, tag)
}

func getCustomClient(gitConfig string) (git.Git, error) {
	gc, ok := cfg.Git[gitConfig]
	if !ok {
		return nil, fmt.Errorf("No Git config specified for: %s!", gitConfig)
	}

	return git.NewGitClient(gc)
}

func remarshalConfig(action string, data []byte) ([]byte, error) {
	// If the action is DELETE, there is no body to remarshal
	if action == "DELETE" {
		data = append(data, []byte("\n")...)
		return data, nil
	}
	config := make(map[string]interface{})
	err := json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	if _, found := config["automatic"]; found {
		delete(config, "automatic")
	}
	c, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}
	c = append(c, []byte("\n")...)
	return decodeMarshalledJSON(c), nil
}

func decodeMarshalledJSON(b []byte) []byte {
	r := strings.NewReplacer(`\u003c`, `<`, `\u003e`, `>`, `\u0026`, `&`)
	s := r.Replace(string(b))
	return []byte(s)
}
