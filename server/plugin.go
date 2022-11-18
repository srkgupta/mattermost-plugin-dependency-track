package main

import (
	"io/ioutil"
	"net/http"
	"path/filepath"
	"sync"

	"github.com/gorilla/mux"
	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/mattermost/mattermost-server/v5/plugin"
	"github.com/pkg/errors"
)

const (
	dtrackUsernameKey    = "_dependencytrackusername"
	dtrackPluginId       = "mattermost-plugin-dependency-track"
	dtrackPluginHomePage = "https://github.com/srkgupta/mattermost-plugin-dependency-track"
)

var dependencytrackToUsernameMappingCallback func(string) string

func registerDependencytrackToUsernameMappingCallback(callback func(string) string) {
	dependencytrackToUsernameMappingCallback = callback
}

// Plugin implements the interface expected by the Mattermost server to communicate between the server and plugin processes.
type Plugin struct {
	plugin.MattermostPlugin

	BotUserID string

	// configurationLock synchronizes access to the configuration.
	configurationLock sync.RWMutex

	// configuration is the active plugin configuration. Consult getConfiguration and
	// setConfiguration for usage.
	configuration *configuration

	httpClient http.Client
	router     *mux.Router
}

func (p *Plugin) OnActivate() error {
	// config := p.getConfiguration()

	// if err := config.IsValid(); err != nil {
	// 	return errors.Wrap(err, "invalid config")
	// }

	if p.API.GetConfig().ServiceSettings.SiteURL == nil {
		return errors.New("siteURL is not set. Please set a siteURL and restart the plugin")
	}

	botID, err := p.Helpers.EnsureBot(&model.Bot{
		Username:    "dependencytrack",
		DisplayName: "DependencyTrack",
		Description: "Created by the DependencyTrack plugin.",
	})
	if err != nil {
		return errors.Wrap(err, "failed to ensure dependencytrack bot")
	}
	p.BotUserID = botID

	bundlePath, err := p.API.GetBundlePath()
	if err != nil {
		return errors.Wrap(err, "couldn't get bundle path")
	}

	profileImage, err := ioutil.ReadFile(filepath.Join(bundlePath, "assets", "logo.png"))
	if err != nil {
		return errors.Wrap(err, "couldn't read profile image")
	}

	appErr := p.API.SetProfileImage(botID, profileImage)
	if appErr != nil {
		return errors.Wrap(appErr, "couldn't set profile image")
	}

	p.initializeRouter()

	registerDependencytrackToUsernameMappingCallback(p.getdependencytrackToUsernameMapping)

	return nil
}

// getdependencytrackToUsernameMapping maps a dependencytrack username to the corresponding Mattermost username, if any.
func (p *Plugin) getdependencytrackToUsernameMapping(dependencytrackUsername string) string {
	user, _ := p.API.GetUser(p.getdependencytrackToUserIDMapping(dependencytrackUsername))
	if user == nil {
		return ""
	}

	return user.Username
}

func (p *Plugin) getdependencytrackToUserIDMapping(dependencytrackUsername string) string {
	userID, _ := p.API.KVGet(dependencytrackUsername + dtrackUsernameKey)
	return string(userID)
}

// See https://developers.mattermost.com/extend/plugins/server/reference/
