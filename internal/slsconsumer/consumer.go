package slsconsumer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	sls "github.com/aliyun/aliyun-log-go-sdk"
	consumer "github.com/aliyun/aliyun-log-go-sdk/consumer"
	"github.com/aliyun/credentials-go/credentials"

	"aliyun-cdn-guard/internal/config"
	"aliyun-cdn-guard/internal/detector"
	"aliyun-cdn-guard/internal/model"
)

type credentialAdapter struct{ credential credentials.Credential }

func (a credentialAdapter) GetCredentials() (sls.Credentials, error) {
	c, err := a.credential.GetCredential()
	if err != nil {
		return sls.Credentials{}, err
	}
	if c.AccessKeyId == nil || c.AccessKeySecret == nil {
		return sls.Credentials{}, fmt.Errorf("credential is missing access key")
	}
	token := ""
	if c.SecurityToken != nil {
		token = *c.SecurityToken
	}
	return sls.Credentials{AccessKeyID: *c.AccessKeyId, AccessKeySecret: *c.AccessKeySecret, SecurityToken: token}, nil
}

type Worker struct{ worker *consumer.ConsumerWorker }

func New(cfg *config.Config, cred credentials.Credential, d *detector.Detector, consumerName string) (*Worker, error) {
	cursor := consumer.END_CURSOR
	var start int64
	switch cfg.SLS.CursorPosition {
	case "begin":
		cursor = consumer.BEGIN_CURSOR
	case "end":
	default:
		cursor = consumer.SPECIAL_TIMER_CURSOR
		var err error
		start, err = config.CursorStartTime(cfg.SLS.CursorPosition)
		if err != nil {
			return nil, err
		}
	}
	logger := sdkLogger{logger: slog.Default()}
	sls.Logger = logger
	option := consumer.LogHubConfig{Endpoint: cfg.SLS.Endpoint, CredentialsProvider: credentialAdapter{cred}, Project: cfg.SLS.Project, Logstore: cfg.SLS.Logstore, ConsumerGroupName: cfg.SLS.ConsumerGroup, ConsumerName: consumerName, CursorPosition: cursor, CursorStartTime: start, DataFetchIntervalInMs: int64(cfg.SLS.FetchIntervalSeconds) * 1000, Region: cfg.SLS.Region, Logger: logger}
	process := func(_ int, groups *sls.LogGroupList, tracker consumer.CheckPointTracker) (string, error) {
		events := make([]model.AccessEvent, 0, detector.BatchSize)
		flush := func() error {
			_, err := d.ProcessBatch(context.Background(), events, 0)
			events = events[:0]
			return err
		}
		for _, group := range groups.GetLogGroups() {
			for _, item := range group.GetLogs() {
				fields := map[string]string{}
				for _, content := range item.GetContents() {
					fields[content.GetKey()] = content.GetValue()
				}
				domain := strings.ToLower(strings.TrimSpace(fields["domain"]))
				d.RecordReceived(domain)
				event, ok := toEvent(fields, int64(item.GetTime()))
				if !ok {
					continue
				}
				events = append(events, event)
				if len(events) == detector.BatchSize {
					if err := flush(); err != nil {
						return "", err
					}
				}
			}
		}
		if err := flush(); err != nil {
			return "", err
		}
		if err := tracker.SaveCheckPoint(false); err != nil {
			return "", err
		}
		return "", nil
	}
	return &Worker{worker: consumer.InitConsumerWorkerWithCheckpointTracker(option, process)}, nil
}
func (w *Worker) Start() { w.worker.Start() }
func (w *Worker) Stop()  { w.worker.StopAndWait() }

func toEvent(fields map[string]string, timestamp int64) (model.AccessEvent, bool) {
	domain := strings.ToLower(strings.TrimSpace(fields["domain"]))
	clientIP := strings.TrimSpace(fields["client_ip"])
	uri := fields["uri"]
	if domain == "" || clientIP == "" {
		slog.Warn("skipping log missing domain/client_ip")
		return model.AccessEvent{}, false
	}
	eventID := strings.TrimSpace(fields["uuid"])
	if eventID == "" {
		raw := strings.Join([]string{fmt.Sprint(timestamp), domain, clientIP, fields["user_agent"], uri, fields["uri_param"]}, "\x00")
		sum := sha256.Sum256([]byte(raw))
		eventID = hex.EncodeToString(sum[:])
	}
	return model.AccessEvent{EventID: eventID, Timestamp: timestamp, Domain: domain, ClientIP: clientIP, UserAgent: fields["user_agent"], URI: uri, URIParam: fields["uri_param"]}, true
}
