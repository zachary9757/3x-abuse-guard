package config

import (
	"strings"
	"testing"
)

func TestExampleYAMLIncludesTelegramNotifyEnv(t *testing.T) {
	yaml := string(ExampleYAML())
	for _, want := range []string{
		`telegram_bot_token_env: THREEX_ABUSE_GUARD_TELEGRAM_BOT_TOKEN`,
		`telegram_chat_id_env: THREEX_ABUSE_GUARD_TELEGRAM_CHAT_ID`,
	} {
		if !strings.Contains(yaml, want) {
			t.Fatalf("example yaml missing %q:\n%s", want, yaml)
		}
	}
}
