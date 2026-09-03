package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// runAuth dispatches the auth subcommands. Only explain exists today; login
// arrives with the token flow (Z-004).
func runAuth(ctx context.Context, env Env, args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(env.Stderr, "usage: trove auth explain [flags]")
		return fmt.Errorf("%w: auth needs a subcommand", ErrUsage)
	}
	switch args[0] {
	case "explain":
		return runAuthExplain(ctx, env, args[1:])
	default:
		fmt.Fprintln(env.Stderr, "usage: trove auth explain [flags]")
		return fmt.Errorf("%w: unknown auth subcommand %q", ErrUsage, args[0])
	}
}

// runAuthExplain asks the server's explainer and formats the answer.
//
// The CLI is a client of the admin API (Q23) and adds formatting only
// (ADR 0015): the decision and every binding in the output came from
// GET /api/v1/auth/explain, so this command, the API, and the UI cannot
// disagree about effective permissions.
func runAuthExplain(ctx context.Context, env Env, args []string) error {
	fs := flag.NewFlagSet("auth explain", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	server := fs.String("server", os.Getenv("TROVE_SERVER"), "server base URL (or TROVE_SERVER)")
	subject := fs.String("subject", "", "subject to explain (default: the calling subject)")
	verb := fs.String("verb", "", "permission verb to explain, e.g. repo:write")
	repo := fs.String("repo", "", "repository the verb applies to (default: the system scope)")
	asJSON := fs.Bool("json", false, "print the server's JSON response unformatted")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if *server == "" {
		return fmt.Errorf("%w: --server or TROVE_SERVER is required", ErrUsage)
	}
	if *verb == "" {
		return fmt.Errorf("%w: --verb is required", ErrUsage)
	}

	query := url.Values{"verb": {*verb}}
	if *subject != "" {
		query.Set("subject", *subject)
	}
	if *repo != "" {
		query.Set("resource", *repo)
	}
	target := strings.TrimSuffix(*server, "/") + "/api/v1/auth/explain?" + query.Encode()

	body, err := getJSON(ctx, target)
	if err != nil {
		return err
	}
	if *asJSON {
		_, err := env.Stdout.Write(body)
		return err
	}
	return formatExplanation(env.Stdout, body)
}

// explanation mirrors the endpoint's wire contract. Field names are the API's
// (ADR 0015); the CLI renames nothing.
type explanation struct {
	Subject struct {
		Name     string `json:"name"`
		Kind     string `json:"kind"`
		Disabled bool   `json:"disabled"`
	} `json:"subject"`
	Verb     string `json:"verb"`
	Resource string `json:"resource"`
	Allowed  bool   `json:"allowed"`
	Matched  []struct {
		Binding  string `json:"binding"`
		Role     string `json:"role"`
		Scope    string `json:"scope"`
		ViaGroup string `json:"via_group"`
	} `json:"matched"`
}

// formatExplanation renders the server's answer for a person: the decision on
// one line, then every contributing binding and the group it came through.
func formatExplanation(w io.Writer, body []byte) error {
	var e explanation
	if err := json.Unmarshal(body, &e); err != nil {
		return fmt.Errorf("the server's response could not be parsed: %w", err)
	}

	var out strings.Builder
	answer := "denied"
	if e.Allowed {
		answer = "allowed"
	}
	fmt.Fprintf(&out, "%s %s on %s for %s", answer, e.Verb, e.Resource, e.Subject.Name)
	if e.Subject.Disabled {
		out.WriteString(" (disabled)")
	}
	out.WriteString("\n")

	if !e.Allowed {
		out.WriteString("  no binding grants it\n")
	}
	for _, m := range e.Matched {
		fmt.Fprintf(&out, "  %s: role %s at %s", m.Binding, m.Role, m.Scope)
		if m.ViaGroup != "" {
			fmt.Fprintf(&out, " (via group %s)", m.ViaGroup)
		}
		out.WriteString("\n")
	}

	_, err := io.WriteString(w, out.String())
	return err
}

// getJSON performs an authenticated GET and returns the body of a 200.
//
// Any other status is reported through the problem document's own words, so
// the operator reads the server's explanation rather than this client's guess.
func getJSON(ctx context.Context, target string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if token := os.Getenv("TROVE_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading the response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, refusal(resp.StatusCode, body)
	}
	return body, nil
}

// refusal turns a non-200 answer into an error in the server's words.
func refusal(status int, body []byte) error {
	var problem struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(body, &problem); err == nil && problem.Title != "" {
		if problem.Detail != "" {
			return fmt.Errorf("server refused (%d): %s: %s", status, problem.Title, problem.Detail)
		}
		return fmt.Errorf("server refused (%d): %s", status, problem.Title)
	}
	return fmt.Errorf("server refused (%d)", status)
}
