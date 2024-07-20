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
	"fmt"
	"os"
	"path"
	"reflect"
	"regexp"
	"strings"

	"github.com/marpaia/chef-golang"
	"github.com/mitchellh/osext"
	"github.com/xanzy/chef-guard/git"
	"gopkg.in/gcfg.v1"
)

type CookbookVersion struct {
	Files []struct {
		chef.CookbookItem
	} `json:"files"`
	Definitions []struct {
		chef.CookbookItem
	} `json:"definitions"`
	Libraries []struct {
		chef.CookbookItem
	} `json:"libraries"`
	Attributes []struct {
		chef.CookbookItem
	} `json:"attributes"`
	Recipes []struct {
		chef.CookbookItem
	} `json:"recipes"`
	Providers []struct {
		chef.CookbookItem
	} `json:"providers"`
	Resources []struct {
		chef.CookbookItem
	} `json:"resources"`
	Templates []struct {
		chef.CookbookItem
	} `json:"templates"`
	AllFiles []struct {
		chef.CookbookItem
	} `json:"all_files"`
	Metadata struct {
		Name            string                 `json:"name"`
		Description     string                 `json:"description"`
		LongDescription string                 `json:"long_description"`
		Maintainer      string                 `json:"maintainer"`
		MaintainerEmail string                 `json:"maintainer_email"`
		License         string                 `json:"license"`
		Platforms       map[string]string      `json:"platforms"`
		Dependencies    map[string]string      `json:"dependencies"`
		Providing       map[string]string      `json:"providing"`
		Attributes      map[string]interface{} `json:"attributes"`
		Recipes         map[string]string      `json:"recipes"`
		Version         string                 `json:"version"`
	} `json:"metadata"`
	Name      string `json:"cookbook_name"`
	Version   string `json:"version"`
	FullName  string `json:"name"`
	Frozen    bool   `json:"frozen?"`
	ChefType  string `json:"chef_type"`
	JSONClass string `json:"json_class"`
}

// Config represents the Chef-Guard configuration
type Config struct {
	Default struct {
		ListenIP           string
		ListenPort         int
		Logfile            string
		Tempdir            string
		Mode               string
		MailDomain         string
		MailServer         string
		MailPort           int
		MailSendBy         string
		MailRecipient      string
		ValidateChanges    string
		CommitChanges      bool
		MailChanges        bool
		SearchGit          bool
		PublishCookbook    bool
		Blacklist          string
		DevEnvironment     string
		GitConfig          string
		GitCookbookConfigs string
		IncludeFCs         string
		ExcludeFCs         string
	}
	Customer map[string]*struct {
		Mode               *string
		MailDomain         *string
		MailServer         *string
		MailPort           *int
		MailSendBy         *string
		MailRecipient      *string
		ValidateChanges    *string
		CommitChanges      *bool
		MailChanges        *bool
		SearchGit          *bool
		PublishCookbook    *bool
		Blacklist          *string
		DevEnvironment     *string
		GitCookbookConfigs *string
		ExcludeFCs         *string
	}
	Chef struct {
		Type            string
		Version         int
		Server          string
		Port            string
		SSLNoVerify     bool
		ErchefIP        string
		ErchefPort      int
		BookshelfKey    string
		BookshelfSecret string
		BookshelfBucket string
		BookshelfDomain string
		BookshelfRegion string
		User            string
		Key             string
	}
	ChefClients struct {
		Path string
	}
	Community struct {
		Supermarket string
		Forks       string
	}
	Supermarket struct {
		Server      string
		Port        string
		SSLNoVerify bool
		User        string
		Key         string
	}
	Tests struct {
		Foodcritic string
		Rubocop    string
	}
	Git map[string]*git.Config
}

var cfg Config

func loadConfig() error {
	exe, err := osext.Executable()
	if err != nil {
		return fmt.Errorf("Failed to get path of %s: %s", path.Base(os.Args[0]), err)
	}

	strings.TrimSuffix(exe, path.Ext(exe))
	var tmpConfig Config
	if err := gcfg.ReadFileInto(&tmpConfig, exe+".conf"); err != nil {
		return fmt.Errorf("Failed to parse config file '%s': %s", exe+".conf", err)
	}

	if err := verifyRequiredFields(&tmpConfig); err != nil {
		return err
	}
	if err := verifyChefConfig(&tmpConfig); err != nil {
		return err
	}
	if err := verifyGitConfigs(&tmpConfig); err != nil {
		return err
	}
	if err := verifyBlackLists(&tmpConfig); err != nil {
		return err
	}
	if err := parsePaths(&tmpConfig, path.Dir(exe)); err != nil {
		return err
	}

	cfg = tmpConfig

	return nil
}

func verifyRequiredFields(c *Config) error {
	r := map[string]interface{}{
		"Default->ListenIP":        c.Default.ListenIP,
		"Default->ListenPort":      c.Default.ListenPort,
		"Default->Logfile":         c.Default.Logfile,
		"Default->Tempdir":         c.Default.Tempdir,
		"Default->Mode":            c.Default.Mode,
		"Default->ValidateChanges": c.Default.ValidateChanges,
		"Chef->Type":               c.Chef.Type,
		"Chef->Version":            c.Chef.Version,
		"Chef->Server":             c.Chef.Server,
		"Chef->Port":               c.Chef.Port,
		"Chef->ErchefIP":           c.Chef.ErchefIP,
		"Chef->ErchefPort":         c.Chef.ErchefPort,
		"Chef->BookshelfKey":       c.Chef.BookshelfKey,
		"Chef->BookshelfSecret":    c.Chef.BookshelfSecret,
		"Chef->BookshelfBucket":    c.Chef.BookshelfBucket,
		"Chef->BookshelfDomain":    c.Chef.BookshelfDomain,
		"Chef->BookshelfRegion":    c.Chef.BookshelfRegion,
		"Chef->User":               c.Chef.User,
		"Chef->Key":                c.Chef.Key,
		"Community->Supermarket":   c.Community.Supermarket,
	}

	if c.Default.MailChanges {
		r["Default->MailServer"] = c.Default.MailServer
		r["Default->MailPort"] = c.Default.MailPort
		r["Default->MailRecipient"] = c.Default.MailRecipient
	}

	if c.Default.CommitChanges {
		r["Default->GitConfig"] = c.Default.GitConfig
	}

	if c.Default.SearchGit {
		r["Default->GitCookbookConfigs"] = c.Default.GitCookbookConfigs
	}

	if c.Default.PublishCookbook {
		r["Supermarket->Server"] = c.Supermarket.Server
		r["Supermarket->Port"] = c.Supermarket.Port
		r["Supermarket->User"] = c.Supermarket.User
		r["Supermarket->Key"] = c.Supermarket.Key
	}

	for k, v := range r {
		switch v := v.(type) {
		case int:
			if v == 0 {
				return fmt.Errorf("Required configuration value missing for Section->Key: %s", k)
			}
		case string:
			if v == "" {
				return fmt.Errorf("Required configuration value missing for Section->Key: %s", k)
			}
		}
	}

	return nil
}

func verifyChefConfig(c *Config) error {
	switch c.Chef.Type {
	case "enterprise", "opensource", "goiardi":
		return nil
	default:
		return fmt.Errorf("Invalid Chef type %q! Valid types are 'enterprise', 'opensource' and 'goiardi'.", c.Chef.Type)
	}
}

func verifyGitConfigs(c *Config) error {
	for k, v := range c.Git {
		if v.Organization == "" {
			v.Organization = k
		}
		if v.Type != "github" && v.Type != "gitlab" {
			return fmt.Errorf("Invalid Git type %q! Valid types are 'github' and 'gitlab'.", v.Type)
		}
		if v.Token == "" {
			return fmt.Errorf("No token found for %s organization %s! All configured organizations need to have a valid token.", v.Type, v.Organization)
		}
	}
	return nil
}

func verifyBlackLists(c *Config) error {
	rgx := strings.Split(c.Default.Blacklist, "|")
	for _, r := range rgx {
		if _, err := regexp.Compile(r); err != nil {
			return fmt.Errorf("The Default blacklist contains a bad regex: %s", err)
		}
	}
	for k, v := range c.Customer {
		if v.Blacklist != nil {
			rgx := strings.Split(*v.Blacklist, "|")
			for _, r := range rgx {
				if _, err := regexp.Compile(r); err != nil {
					return fmt.Errorf("The blacklist for customer %s contains a bad regex: %s", k, err)
				}
			}
		}
	}
	return nil
}

func parsePaths(c *Config, ep string) error {
	if !path.IsAbs(c.Default.Logfile) {
		c.Default.Logfile = path.Join(ep, c.Default.Logfile)
	}
	if c.Tests.Foodcritic != "" && !path.IsAbs(c.Tests.Foodcritic) {
		c.Tests.Foodcritic = path.Join(ep, c.Tests.Foodcritic)
	}
	if c.Tests.Rubocop != "" && !path.IsAbs(c.Tests.Rubocop) {
		c.Tests.Rubocop = path.Join(ep, c.Tests.Rubocop)
	}
	return nil
}

func getEffectiveConfig(key, chefOrg string) interface{} {
	if cfg.Chef.Type == "enterprise" {
		if c, found := cfg.Customer[chefOrg]; found {
			conf := reflect.ValueOf(c).Elem()
			v := conf.FieldByName(key)
			if !v.IsNil() {
				return v.Elem().Interface()
			}
		}
	}
	c := reflect.ValueOf(cfg.Default)
	return c.FieldByName(key).Interface()
}
