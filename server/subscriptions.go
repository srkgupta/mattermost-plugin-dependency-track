package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/pkg/errors"
)

const (
	SubscriptionsKey = "subscriptions"
	WebhookAPI       = "subscriptions"
)

type Subscription struct {
	ChannelID string
	CreatorID string
}

type Subscriptions struct {
	Subscriptions []*Subscription
}

func (p *Plugin) Subscribe(userID string, channelID string) error {

	sub := &Subscription{
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

func (p *Plugin) Unsubscribe(index int) error {
	subs, err := p.GetSubscriptions()
	if err != nil {
		return errors.Wrap(err, "could not get subscriptions")
	}

	if index < 1 || index > len(subs) {
		return errors.Errorf("Invalid subscription index. Note: index starts with 1")
	}

	newSubs := []*Subscription{}

	for i, sub := range subs {
		if i != index-1 {
			newSubs = append(newSubs, sub)
		}
	}

	if err := p.StoreSubscriptions(newSubs); err != nil {
		return errors.Wrap(err, "could not store subscriptions")
	}

	return nil
}

func (p *Plugin) executeSubscriptions(args *model.CommandArgs, split []string) (*model.CommandResponse, *model.AppError) {
	if 0 >= len(split) {
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
			msg := "Please specify the index of the subscription to be removed. You can run the command '/dependency-track subscriptions list' to get the index position."
			return p.sendEphemeralResponse(args, msg), nil
		} else {
			return p.handleUnsubscribe(args, split[1])
		}
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
	msg := "Subscription successful."
	return p.sendEphemeralResponse(args, msg), nil
}

func (p *Plugin) handleUnsubscribe(args *model.CommandArgs, indexStr string) (*model.CommandResponse, *model.AppError) {
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		msg := fmt.Sprintf("Something went wrong while unsubscribing. Error: %s\n", err.Error())
		return p.sendEphemeralResponse(args, msg), nil
	}
	err = p.Unsubscribe(index)
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
	if len(subs) == 0 {
		msg = "Currently there are no channels subscribed to receive DependencyTrack notifications."
	} else {
		msg = "Channels subscribed to receive DependencyTrack notifications:\n"
		for i, v := range subs {
			channel, _ := p.API.GetChannel(v.ChannelID)
			msg += fmt.Sprintf("%d. ~%s\n", i+1, channel.Name)
		}
	}
	return p.sendEphemeralResponse(args, msg), nil

}
