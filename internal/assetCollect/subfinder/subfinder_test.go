package subfinder

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"
	"testing"

	"bg-agent/internal/assetCollect/subfinder/pkg/passive"
	"bg-agent/internal/assetCollect/subfinder/pkg/resolve"
	"bg-agent/internal/assetCollect/subfinder/pkg/runner"

	"github.com/projectdiscovery/gologger"
)

func TestLocalSubfinder(t *testing.T) {

	runnerInstance, err := runner.NewRunner(&runner.Options{
		Silent: true,
		All:    true,
		// ProviderConfig: ,
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		RemoveWildcard:     true,
		Resolvers:          resolve.DefaultResolvers, // Use the default list of resolvers by marshaling it to the config
		ResultCallback: func(s *resolve.HostEntry) { // Callback function to execute for available host
			// log.Println(s.Host, s.Source)
		},
	})
	sourceApiKeysMap := map[string][]string{
		"shodan":     []string{"U5ityH3ya9gcGMrKdvHcaKD2xyJEsgn8"},
		"fofa":       []string{"zjgelen@gmail.com:1bd13cc61d22823099fea2a8e26f7478"},
		"virustotal": []string{"209e09bd70fb39a37987218def266691e0bb834a91b26d56039eed82c02b2e71"},
		"urlscan":    []string{"f40240d3-54a6-4778-a401-7d83e6ee83ac"},
		"threatbook": []string{"f7bff3be38934f778d70c7a5fc6097387638c347625d41379a6f6ca0f2ae89e0"},
		"spyse":      []string{"65b8676c-1d61-4915-8718-a324b64a36a8"},
		"github":     []string{"p_VdG9J5LR6TBLOPDiVTJLbJGqJA0yjU0J7aHS"},
		"censys":     []string{"5bd2a5da-abf7-4f9b-b216-16fa003c9d1d"},
		"chinaz":     []string{"4b20375e736a40b181dc380f41c391cd"},
	}

	for _, source := range passive.AllSources {
		sourceName := strings.ToLower(source.Name())
		apiKeys := sourceApiKeysMap[sourceName]
		if source.NeedsKey() && apiKeys != nil && len(apiKeys) > 0 {
			gologger.Debug().Msgf("API key(s) found for %s.", sourceName)
			source.AddApiKeys(apiKeys)
		}
	}

	buf := bytes.Buffer{}
	err = runnerInstance.EnumerateSingleDomain("sf-express.com", []io.Writer{&buf})
	if err != nil {
		log.Fatal(err)
	}

	data, err := io.ReadAll(&buf)
	if err != nil {
		log.Fatal(err)
	}

	scanner := bufio.NewScanner(bytes.NewBuffer(data))
	for scanner.Scan() {
		line := scanner.Text()
		log.Println(line)
	}
	// fmt.Printf("%s", data)
}

func b123TestColletBySubfinder(t *testing.T) {

	// providers := runner.Providers{}

	runnerInstance, err := runner.NewRunner(&runner.Options{
		// ProviderConfig: ,
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		RemoveWildcard:     true,
		Resolvers:          resolve.DefaultResolvers, // Use the default list of resolvers by marshaling it to the config
		ResultCallback: func(s *resolve.HostEntry) { // Callback function to execute for available host
			log.Println(s.Host, s.Source)
		},
	})

	buf := bytes.Buffer{}
	err = runnerInstance.EnumerateSingleDomain("sf-express.com", []io.Writer{&buf})
	if err != nil {
		log.Fatal(err)
	}

	data, err := io.ReadAll(&buf)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", data)
}
