package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/pkg/errors"
)

const (
	SubscriptionsKey = "subscriptions"
)

type Subscription struct {
	ID        string
	ChannelID string
	CreatorID string
}

type Subscriptions struct {
	Subscriptions []*Subscription
}

func generateUUIDName() string {
	id := uuid.New()
	return (id.String())
}

func (p *Plugin) Subscribe(userID string, channelID string) error {

	sub := &Subscription{
		ID:        generateUUIDName(),
		ChannelID: channelID,
		CreatorID: userID,
	}

	if err := p.AddSubscription(sub); err != nil {
		return errors.Wrap(err, "could not add subscription")
	}

	return nil
}

func (p *Plugin) GetSubscriptionByChannel(channelID string) (*Subscription, error) {
	var filteredSub *Subscription
	subs, err := p.GetSubscriptions()
	if err != nil {
		return nil, errors.Wrap(err, "could not get subscriptions")
	}

	for _, sub := range subs {
		if sub.ChannelID == channelID {
			filteredSub = sub
			break
		}
	}

	return filteredSub, nil
}

func (p *Plugin) AddSubscription(sub *Subscription) error {
	subs, err := p.GetSubscriptions()
	if err != nil {
		return errors.Wrap(err, "could not get subscriptions")
	}
	exists := false
	for _, v := range subs {
		if v.ChannelID == sub.ChannelID {
			exists = true
			break
		}
	}

	if !exists {
		subs = append(subs, sub)
	}

	err = p.StoreSubscriptions(subs)
	if err != nil {
		return errors.Wrap(err, "could not store subscriptions")
	}

	return nil
}

func (p *Plugin) GetSubscriptions() ([]*Subscription, error) {
	var subscriptions []*Subscription

	value, appErr := p.API.KVGet(SubscriptionsKey)
	if appErr != nil {
		return nil, errors.Wrap(appErr, "could not get subscriptions from KVStore")
	}

	if value == nil {
		return []*Subscription{}, nil
	}

	err := json.NewDecoder(bytes.NewReader(value)).Decode(&subscriptions)
	if err != nil {
		return nil, errors.Wrap(err, "could not properly decode subscriptions key")
	}

	return subscriptions, nil
}

func (p *Plugin) StoreSubscriptions(s []*Subscription) error {
	b, err := json.Marshal(s)
	if err != nil {
		return errors.Wrap(err, "error while converting subscriptions to json")
	}

	if appErr := p.API.KVSet(SubscriptionsKey, b); appErr != nil {
		return errors.Wrap(appErr, "could not store subscriptions in KV store")
	}

	return nil
}

func (p *Plugin) Unsubscribe(id string) error {
	subs, err := p.GetSubscriptions()
	if err != nil {
		return errors.Wrap(err, "could not get subscriptions")
	}

	newSubs := []*Subscription{}

	for _, sub := range subs {
		if sub.ID != id {
			newSubs = append(newSubs, sub)
		}
	}

	if err := p.StoreSubscriptions(newSubs); err != nil {
		return errors.Wrap(err, "could not store subscriptions")
	}

	return nil
}

func (p *Plugin) executeSubscriptions(args *model.CommandArgs, split []string) (*model.CommandResponse, *model.AppError) {
	if len(split) <= 0 {
		msg := "Invalid subscribe command. Available commands are 'list', 'add' and 'delete'."
		return p.sendEphemeralResponse(args, msg), nil
	}

	command := split[0]

	switch {
	case command == "list":
		return p.handleSubscriptionsList(args)
	case command == "add":
		return p.handleSubscribesAdd(args)
	case command == "delete":
		if len(split) < 2 {
			msg := "Please specify the subscriptionId to be removed. You can run the command '/dtrack subscriptions list' to get the subscriptionId."
			return p.sendEphemeralResponse(args, msg), nil
		}
		return p.handleUnsubscribe(args, split[1])
	default:
		msg := "Unknown subcommand for subscribe command. Available commands are 'list', 'add' and 'delete'."
		return p.sendEphemeralResponse(args, msg), nil
	}
}

func (p *Plugin) handleSubscribesAdd(args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {

	err := p.Subscribe(args.UserId, args.ChannelId)
	if err != nil {
		msg := fmt.Sprintf("Something went wrong while subscribing. Error: %s\n", err.Error())
		return p.sendEphemeralResponse(args, msg), nil
	}
	msg := fmt.Sprintf(
		":white_check_mark: Subscription saved! \n"+
			"#### How to finish setup:\n"+
			"(See the full guide [here](%s/admin-guide/configuration))\n"+
			"1. Create a New Outbound Webhook in the DependencyTrack tool. [Instructions here](https://docs.dependencytrack.org/integrations/notifications/)\n"+
			"2. Set the Webhook URL as: `%s`\n"+
			"3. Enable Notifications for following types of notifications: \n"+
			"	- NEW_VULNERABILITY\n"+
			"	- NEW_VULNERABLE_DEPENDENCY\n"+
			"	- BOM_CONSUMED (Optional)\n"+
			"	- BOM_PROCESSED (Optional)\n"+
			"\n\n**Webhook URL: `%s`**",
		dtrackPluginHomePage,
		p.getWebhookURL(),
		p.getWebhookURL(),
	)
	return p.sendEphemeralResponse(args, msg), nil
}

func (p *Plugin) handleUnsubscribe(args *model.CommandArgs, ID string) (*model.CommandResponse, *model.AppError) {
	err := p.Unsubscribe(ID)
	if err != nil {
		msg := fmt.Sprintf("Something went wrong while unsubscribing. Error: %s\n", err.Error())
		return p.sendEphemeralResponse(args, msg), nil
	}
	msg := "Successfully unsubscribed! The specified channel will not receive DependencyTrack notifications."
	return p.sendEphemeralResponse(args, msg), nil
}

func (p *Plugin) handleSubscriptionsList(args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {
	subs, err := p.GetSubscriptions()
	msg := ""
	if err != nil {
		msg = fmt.Sprintf("Something went wrong while checking for subscriptions. Error: %s\n", err.Error())
		return p.sendEphemeralResponse(args, msg), nil
	}

	value := ""

	if len(subs) == 0 {
		value = "No channels are subscribed to receive any notifications from DependencyTrack tool."
	} else {
		value = "| Subscription ID | Channel | Subscribed By |\n"
		value += "| ----------- | ----------- | ----------- | \n"
	}

	for _, sub := range subs {
		username := "Unknown user"
		if user, appErr := p.API.GetUser(sub.CreatorID); appErr != nil {
			p.API.LogError("Unable to get username", "userID", sub.CreatorID)
		} else {
			username = user.Username
		}
		channel, _ := p.API.GetChannel(sub.ChannelID)
		value += fmt.Sprintf("| %s | ~%s | @%s |\n", sub.ID, channel.Name, username)
	}

	attachment := model.SlackAttachment{
		Title: "Channels subscribed to receive DependencyTrack Notifications:",
		Text:  value,
	}

	p.sendEphemeralPost(args, "", []*model.SlackAttachment{&attachment})
	return &model.CommandResponse{}, nil

}
