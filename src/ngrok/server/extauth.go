package server

import (
	"bytes"
	"encoding/json"
	"fmt"
//	"io/ioutil"
	"net/http"
	"ngrok/log"
	"ngrok/msg"
	"sort"
	"strings"
)

type ExtAuth struct {
	url string
	log.Logger
}

type Rights struct {
	data rightsData
}

type rightsData struct {
	AllowedHostnames          []string
	AllowedSubdomains         []string
	AllowedPorts              []int
	AutomaticPortAllowed      bool
	AutomaticSubdomainAllowed bool
	AllowAll                  bool
}

// Creates a new ExtAuth object
func NewExtAuth(u string) *ExtAuth {
	e := &ExtAuth{
		url: u,
		Logger: log.NewPrefixLogger(),
	}

	return e
}

// Verifies that the Auth request is valid and returns an ExtAuthSession
func (ea *ExtAuth) Auth(authMsg *msg.Auth) (*Rights, error) {
	var r Rights;

	if ea.url == "" {
		r.data.AllowAll = true
		return &r, nil
	}

	b := []byte(`{"Token":"` + authMsg.User + `"}`)
	resp, err := http.Post(ea.url, "application/json", bytes.NewBuffer(b))

	log.Debug("External authentification request: " + `{"Token":"` + authMsg.User + `"}`)

	if err != nil {
		log.Warn(err.Error())
		err = fmt.Errorf("External authentification unavailable")
		return &r, err
	}

	defer resp.Body.Close()

//	body, _ := ioutil.ReadAll(resp.Body)
//	bodyString := string(body)
//	log.Debug(bodyString)
//	err = json.Unmarshal(body, &(r.data))

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&(r.data))

	if err != nil {
		log.Warn(err.Error())
		err = fmt.Errorf("External authentification unavailable")
		return &r, err
	}

	sort.Strings(r.data.AllowedHostnames)
	sort.Strings(r.data.AllowedSubdomains)
	sort.Ints(r.data.AllowedPorts)

	return &r, err
}

// Verifies that the tunnel request is valid
func (r * Rights) RequestTunnel(rawTunnelReq *msg.ReqTunnel) error {
	if r.data.AllowAll {
		return nil
	}

	switch rawTunnelReq.Protocol {
	case "tcp":
		port := int(rawTunnelReq.RemotePort)
		if port!=0 {
			i := sort.SearchInts(r.data.AllowedPorts, port)
			if i < len(r.data.AllowedPorts) && r.data.AllowedPorts[i] == port {
				return nil
			}
			err := fmt.Errorf("Port %d not allowed for this session", port)
			return err
		}
		if r.data.AutomaticPortAllowed {
			return nil
		}
		err := fmt.Errorf("Automatic port not allowed for this session")
		return err
	case "http", "https":
		hostname := strings.ToLower(strings.TrimSpace(rawTunnelReq.Hostname))
		if hostname != "" {
			i := sort.SearchStrings(r.data.AllowedHostnames, hostname)
			if i < len(r.data.AllowedHostnames) && r.data.AllowedHostnames[i] == hostname {
				return nil
			}
			err := fmt.Errorf("Hostname %s not allowed for this session", hostname)
			return err
		}
		subdomain := strings.ToLower(strings.TrimSpace(rawTunnelReq.Subdomain))
		if subdomain != "" {
			i := sort.SearchStrings(r.data.AllowedSubdomains, subdomain)
			if i < len(r.data.AllowedSubdomains) && r.data.AllowedSubdomains[i] == subdomain {
				return nil
			}
			err := fmt.Errorf("Subdomain %s not allowed for this session", subdomain)
			return err
		}
		if r.data.AutomaticSubdomainAllowed {
			return nil
		}
		err := fmt.Errorf("Automatic subdomain not allowed for this session")
		return err
	default:
		err := fmt.Errorf("Protocol %s is not supported", rawTunnelReq.Protocol)
		return err
	}

	err := fmt.Errorf("Request rejected for unknow reason")
	return err
}
