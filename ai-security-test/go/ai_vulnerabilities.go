// AI Security Test Cases - Go
// INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
// Copyright © 2026 Sthenos Security. Test file only.

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	openai "github.com/sashabaranov/go-openai"
)

// === LLM01: PROMPT INJECTION ===

// VulnerableDirectInput - VULNERABLE: User input directly in prompt
func VulnerableDirectInput(userMessage string) (string, error) {
	client := openai.NewClient(os.Getenv("OPENAI_API_KEY"))

	// BAD: User input directly in prompt
	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT4,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleSystem,
					Content: "You are a helpful assistant.",
				},
				{
					Role:    openai.ChatMessageRoleUser,
					Content: userMessage, // Direct user input
				},
			},
		},
	)

	if err != nil {
		return "", err
	}

	return resp.Choices[0].Message.Content, nil
}

// VulnerableFmtSprintf - VULNERABLE: Format string injection
func VulnerableFmtSprintf(userQuery string) (string, error) {
	client := openai.NewClient(os.Getenv("OPENAI_API_KEY"))

	// BAD: User input in fmt.Sprintf
	prompt := fmt.Sprintf("Answer this question: %s", userQuery)

	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT4,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: prompt,
				},
			},
		},
	)

	if err != nil {
		return "", err
	}

	return resp.Choices[0].Message.Content, nil
}

// VulnerableSystemPromptOverride - VULNERABLE: User controls system prompt
func VulnerableSystemPromptOverride(userSystemPrompt string) (string, error) {
	client := openai.NewClient(os.Getenv("OPENAI_API_KEY"))

	// BAD: User controls system prompt
	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT4,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleSystem,
					Content: userSystemPrompt, // User controls system!
				},
				{
					Role:    openai.ChatMessageRoleUser,
					Content: "Hello",
				},
			},
		},
	)

	if err != nil {
		return "", err
	}

	return resp.Choices[0].Message.Content, nil
}

// === LLM02: SENSITIVE DISCLOSURE ===

// VulnerableAPIKeyInPrompt - VULNERABLE: API key exposed to model
func VulnerableAPIKeyInPrompt() (string, error) {
	client := openai.NewClient(os.Getenv("OPENAI_API_KEY"))

	// BAD: API key in prompt
	apiKey := "sk-1234567890abcdef"
	prompt := fmt.Sprintf("Use this API key to authenticate: %s", apiKey)

	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT4,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: prompt,
				},
			},
		},
	)

	if err != nil {
		return "", err
	}

	return resp.Choices[0].Message.Content, nil
}

// VulnerablePIIExposure - VULNERABLE: PII sent to model
type UserData struct {
	Name       string
	SSN        string
	CreditCard string
}

func VulnerablePIIExposure(userData UserData) (string, error) {
	client := openai.NewClient(os.Getenv("OPENAI_API_KEY"))

	// BAD: Raw PII sent to model
	prompt := fmt.Sprintf("Process customer: Name=%s, SSN=%s, CC=%s",
		userData.Name, userData.SSN, userData.CreditCard)

	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT4,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: prompt,
				},
			},
		},
	)

	if err != nil {
		return "", err
	}

	return resp.Choices[0].Message.Content, nil
}

// === LLM05: IMPROPER OUTPUT HANDLING ===

// VulnerableShellExecution - VULNERABLE: Running LLM output as shell command
func VulnerableShellExecution(prompt string) (string, error) {
	client := openai.NewClient(os.Getenv("OPENAI_API_KEY"))

	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT4,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleSystem,
					Content: "Generate a shell command",
				},
				{
					Role:    openai.ChatMessageRoleUser,
					Content: prompt,
				},
			},
		},
	)

	if err != nil {
		return "", err
	}

	command := resp.Choices[0].Message.Content

	// BAD: Executing LLM output as shell command
	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(output), nil
}

// VulnerableExecCommand - VULNERABLE: exec.Command with LLM output
func VulnerableExecCommand(prompt string) (string, error) {
	client := openai.NewClient(os.Getenv("OPENAI_API_KEY"))

	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT4,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: prompt,
				},
			},
		},
	)

	if err != nil {
		return "", err
	}

	cmdStr := resp.Choices[0].Message.Content

	// BAD: Direct command execution
	cmd := exec.Command(cmdStr)
	output, _ := cmd.CombinedOutput()
	return string(output), nil
}

// === LLM06: EXCESSIVE AGENCY ===

// VulnerableDangerousTool - VULNERABLE: Agent with dangerous tool
type DangerousTool struct{}

func (t *DangerousTool) Execute(command string) (string, error) {
	// BAD: Unrestricted shell execution
	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.Output()
	return string(output), err
}

func (t *DangerousTool) DeleteFile(path string) error {
	// BAD: No path validation
	return os.Remove(path)
}

func (t *DangerousTool) WriteFile(path, content string) error {
	// BAD: Can write anywhere
	return os.WriteFile(path, []byte(content), 0644)
}

// VulnerableFileOperations - VULNERABLE: Unrestricted file operations
func VulnerableFileOperations(llmOutput string) error {
	// BAD: LLM output controls file operations
	return os.WriteFile("/tmp/output.txt", []byte(llmOutput), 0644)
}

// === SAFE PATTERNS ===

// SafeSanitizedInput - SAFE: Input sanitized before use
func SafeSanitizedInput(userMessage string) (string, error) {
	client := openai.NewClient(os.Getenv("OPENAI_API_KEY"))

	// GOOD: Sanitize input
	sanitized := userMessage
	if len(sanitized) > 1000 {
		sanitized = sanitized[:1000]
	}

	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT4,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleSystem,
					Content: "You are a helpful assistant.",
				},
				{
					Role:    openai.ChatMessageRoleUser,
					Content: sanitized,
				},
			},
		},
	)

	if err != nil {
		return "", err
	}

	return resp.Choices[0].Message.Content, nil
}

// SafeRestrictedTool - SAFE: Tool with whitelist
type SafeRestrictedTool struct {
	allowedCommands map[string]bool
}

func NewSafeRestrictedTool() *SafeRestrictedTool {
	return &SafeRestrictedTool{
		allowedCommands: map[string]bool{
			"ls":   true,
			"pwd":  true,
			"date": true,
		},
	}
}

func (t *SafeRestrictedTool) Execute(command string) (string, error) {
	// GOOD: Whitelist check
	if !t.allowedCommands[command] {
		return "", fmt.Errorf("command not allowed: %s", command)
	}

	cmd := exec.Command(command)
	output, err := cmd.Output()
	return string(output), err
}

func main() {
	// Test vulnerable functions
	fmt.Println("AI Security Test Cases - Go")
}
