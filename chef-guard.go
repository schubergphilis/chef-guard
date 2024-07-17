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
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/icub3d/graceful"
	"github.com/marpaia/chef-golang"
	"github.com/xanzy/chef-guard/git"
)

// VERSION holds the current version
const VERSION = "0.7.3"

var chefKey string

var insecureTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	Dial: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).Dial,
	TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	TLSHandshakeTimeout: 10 * time.Second,
}

// The ChefGuard struct holds all required info needed to process a request made through Chef-Guard
type ChefGuard struct {
	smClient       *chef.Chef
	chefClient     *chef.Chef
	gitClient      git.Git
	User           string
	Repo           string
	ChefOrg        string
	ChefOrgID      *string
	Cookbook       *CookbookVersion
	CookbookPath   string
	SourceCookbook *SourceCookbook
	ChangeDetails  *changeDetails
	ForcedUpload   bool
	FileHashes     map[string][16]byte
	GitIgnoreFile  []byte
	ChefIgnoreFile []byte
	TarFile        []byte
}

func newChefGuard(r *http.Request) (*ChefGuard, error) {
	cg := &ChefGuard{
		User:         r.Header.Get("X-Ops-Userid"),
		ChefOrg:      getChefOrgFromRequest(r),
		ForcedUpload: dropForce(r),
	}

	// Set the repo dependend on the Organization (could become a configurable in the future)
	if cg.ChefOrg != "" {
		cg.Repo = cg.ChefOrg
	} else {
		cg.Repo = "config"
	}

	// Initialize map for the file hashes
	cg.FileHashes = map[string][16]byte{}

	// Load the Chef key
	if chefKey == "" {
		key, err := ioutil.ReadFile(cfg.Chef.Key)
		if err != nil {
			return nil, fmt.Errorf("Failed to read Chef key: %s", err)
		}

		chefKey = string(key)
	}

	// Setup chefClient
	var err error
	cg.chefClient, err = chef.ConnectBuilder(cfg.Chef.Server, cfg.Chef.Port, "", cfg.Chef.User, chefKey, cg.ChefOrg)
	if err != nil {
		return nil, fmt.Errorf("Failed to create new Chef API connection: %s", err)
	}

	cg.chefClient.SSLNoVerify = cfg.Chef.SSLNoVerify

	return cg, nil
}

func main() {
	version := flag.Bool("v", false, "Show version")
	flag.Parse()

	if *version {
		fmt.Println("Version: " + VERSION)
		return
	}

	// Load and parse the config file
	if err := loadConfig(); err != nil {
		log.Fatal(err)
	}
	// Initialize logging
	if err := initLogging(); err != nil {
		log.Fatal(err)
	}
	// Parse the ErChef API URL
	u, err := url.Parse(fmt.Sprintf("http://%s:%d", cfg.Chef.ErchefIP, cfg.Chef.ErchefPort))
	if err != nil {
		log.Fatal(fmt.Errorf("Failed to parse ErChef API URL %s: %s", fmt.Sprintf("http://%s:%d", cfg.Chef.ErchefIP, cfg.Chef.ErchefPort), err))
	}
	// All critical parts are started now, so let's log a 'started' message :)
	INFO.Println("Server started...")

	// Setup the ErChef proxy
	p := httputil.NewSingleHostReverseProxy(u)

	// Configure all needed handlers
	rtr := mux.NewRouter()
	if cfg.Chef.Type == "enterprise" || cfg.Chef.Version > 11 {
		rtr.Path("/organizations/{org}/{type:data}/{bag}").HandlerFunc(processChange(p)).Methods("POST", "DELETE")
		rtr.Path("/organizations/{org}/{type:data}/{bag}/{name}").HandlerFunc(processChange(p)).Methods("PUT", "DELETE")
		rtr.Path("/organizations/{org}/{type:clients|environments|nodes|roles}").HandlerFunc(processChange(p)).Methods("POST")
		rtr.Path("/organizations/{org}/{type:clients|environments|nodes|roles}/{name}").HandlerFunc(processChange(p)).Methods("PUT", "DELETE")
		rtr.Path("/organizations/{org}/{type:cookbooks}/{name}/{version}").HandlerFunc(processCookbook(p)).Methods("PUT", "DELETE")
	} else {
		rtr.Path("/{type:data}/{bag}").HandlerFunc(processChange(p)).Methods("POST", "DELETE")
		rtr.Path("/{type:data}/{bag}/{name}").HandlerFunc(processChange(p)).Methods("PUT", "DELETE")
		rtr.Path("/{type:clients|environments|nodes|roles}").HandlerFunc(processChange(p)).Methods("POST")
		rtr.Path("/{type:clients|environments|nodes|roles}/{name}").HandlerFunc(processChange(p)).Methods("PUT", "DELETE")
		rtr.Path("/{type:cookbooks}/{name}/{version}").HandlerFunc(processCookbook(p)).Methods("PUT", "DELETE")
	}

	// Adding some non-Chef endpoints here
	rtr.Path("/chef-guard/time").HandlerFunc(timeHandler).Methods("GET")
	if cfg.ChefClients.Path != "" {
		rtr.Path("/chef-guard/{type:metadata|download}").HandlerFunc(processDownload).Methods("GET")
		rtr.Path("/chef-guard/clients").Handler(http.RedirectHandler("/chef-guard/clients/", http.StatusMovedPermanently))
		rtr.PathPrefix("/chef-guard/clients/").Handler(http.StripPrefix("/chef-guard/clients/", http.FileServer(http.Dir(cfg.ChefClients.Path))))
	}

	rtr.NotFoundHandler = p
	rtr.MethodNotAllowedHandler = p
	http.Handle("/", rtr)

	// Start the server
	shutdownCh := startSignalHandler()
	go func() {
		<-shutdownCh
		msg := "Gracefully closing connections..."
		INFO.Println(msg)
		log.Println(msg)
		graceful.Close()
	}()

	err = graceful.ListenAndServe(fmt.Sprintf("%s:%d", cfg.Default.ListenIP, cfg.Default.ListenPort), nil)
	if err != nil {
		log.Fatalf("Chef-Guard server error: %s", err)
	}

	msg := "Server stopped..."
	INFO.Println(msg)
	log.Println(msg)
}

func startSignalHandler() chan struct{} {
	resultCh := make(chan struct{})

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		count := 0
		for s := range c {
			switch s {
			case syscall.SIGHUP:
				if err := loadConfig(); err != nil {
					msg := fmt.Sprintf("Could not reload configuration: %v", err)
					WARNING.Println(msg)
					log.Println(msg)
				} else {
					msg := "Successfully reloaded configuration!"
					INFO.Println(msg)
					log.Println(msg)
				}
			default:
				if count > 0 {
					msg := "Forcefully stopped Chef-Guard!"
					INFO.Println(msg)
					log.Println(msg)
					os.Exit(0)
				}
				count++
				resultCh <- struct{}{}
			}
		}
	}()

	return resultCh
}

func errorHandler(w http.ResponseWriter, err string, statusCode int) {
	switch statusCode {
	case http.StatusPreconditionFailed:
		// No need to write anything to the log for this one...
	case http.StatusNotFound:
		WARNING.Println(err)
	default:
		ERROR.Println(err)
	}
	http.Error(w, err, statusCode)
}

func getChefOrgFromRequest(r *http.Request) string {
	if cfg.Chef.Type != "enterprise" {
		return ""
	}
	return mux.Vars(r)["org"]
}

func dropForce(r *http.Request) bool {
	v := r.URL.Query()
	if _, exists := v["force"]; exists {
		v.Del("force")
		r.URL.RawQuery = v.Encode()
		return true
	}
	return false
}
