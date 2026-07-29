// Example of using ShrikeOpenAI client.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/sashabaranov/go-openai"
	shrikeopenai "github.com/shrike-security/shrike-guard-go/openai"
)

func main() {
	// Create a Shrike-protected OpenAI client
	client, err := shrikeopenai.NewClient(shrikeopenai.ClientOptions{
		OpenAIAPIKey: os.Getenv("OPENAI_API_KEY"),
		ShrikeAPIKey: os.Getenv("SHRIKE_API_KEY"),
		// Optional: ShrikeEndpoint: "https://custom-endpoint.com",
		// Optional: FailMode: shrike.FailModeOpen, // default is FailModeClosed
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Use just like the regular OpenAI client
	// All prompts are automatically scanned before being sent to OpenAI
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
					Content: "Hello, how are you?",
				},
			},
		},
	)

	if err != nil {
		// Check if blocked by Shrike
		log.Fatalf("Request failed: %v", err)
	}

	fmt.Println("Response:", resp.Choices[0].Message.Content)

	// You can also scan SQL queries and file paths separately
	sqlResult, err := client.ScanSQL(
		context.Background(),
		"SELECT * FROM users WHERE id = 1",
		"production_db",
		false, // allowDestructive
	)
	if err != nil {
		log.Fatalf("SQL scan failed: %v", err)
	}
	fmt.Printf("SQL safe: %v\n", sqlResult.Safe)

	fileResult, err := client.ScanFile(
		context.Background(),
		"/app/data/report.csv",
		"", // optional content
	)
	if err != nil {
		log.Fatalf("File scan failed: %v", err)
	}
	fmt.Printf("File safe: %v\n", fileResult.Safe)
}
