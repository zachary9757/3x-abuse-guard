package notify

import (
	"context"
	"errors"
)

var errQueueFull = errors.New("notification queue is full")

// Delivery sends an event or queues it for sending, reporting failures to onFailure.
type Delivery func(event Event, onFailure func(error))

type queuedEvent struct {
	event     Event
	onFailure func(error)
}

type Queue struct {
	notifier Notifier
	events   chan queuedEvent
}

func NewQueue(notifier Notifier, capacity int) *Queue {
	return &Queue{notifier: notifier, events: make(chan queuedEvent, capacity)}
}

// Deliver queues an event without waiting for the network or for space in the queue.
func (q *Queue) Deliver(event Event, onFailure func(error)) {
	select {
	case q.events <- queuedEvent{event: event, onFailure: onFailure}:
	default:
		onFailure(errQueueFull)
	}
}

func (q *Queue) Run(ctx context.Context) {
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return
		case message := <-q.events:
			if err := q.notifier.Notify(ctx, message.event); err != nil {
				message.onFailure(err)
			}
		}
	}
}
