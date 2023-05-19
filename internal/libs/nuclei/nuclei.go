package nuclei

func BugScanByNuclei(target []string) {
	// cache := hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount)
	// defer cache.Close()

	// mockProgress := &testutils.MockProgressClient{}
	// reportingClient, _ := reporting.New(&reporting.Options{}, "")
	// defer reportingClient.Close()

	// outputWriter := testutils.NewMockOutputWriter()
	// outputWriter.WriteCallback = func(event *output.ResultEvent) {
	// 	fmt.Printf("Got Result: %v\n", event)
	// }

	// defaultOpts := types.DefaultOptions()
	// protocolstate.Init(defaultOpts)
	// protocolinit.Init(defaultOpts)

	// defaultOpts.Templates = goflags.StringSlice{"dns/cname-service.yaml"}
	// defaultOpts.ExcludeTags = config.ReadIgnoreFile().Tags

	// interactOpts := interactsh.NewDefaultOptions(outputWriter, reportingClient, mockProgress)
	// interactClient, err := interactsh.New(interactOpts)
	// if err != nil {
	// 	log.Fatalf("Could not create interact client: %s\n", err)
	// }
	// defer interactClient.Close()

	// home, _ := os.UserHomeDir()
	// catalog := disk.NewCatalog(path.Join(home, "nuclei-templates"))
	// executerOpts := protocols.ExecuterOptions{
	// 	Output:          outputWriter,
	// 	Options:         defaultOpts,
	// 	Progress:        mockProgress,
	// 	Catalog:         catalog,
	// 	IssuesClient:    reportingClient,
	// 	RateLimiter:     ratelimit.New(context.Background(), 150, time.Second),
	// 	Interactsh:      interactClient,
	// 	HostErrorsCache: cache,
	// 	Colorizer:       aurora.NewAurora(true),
	// 	ResumeCfg:       types.NewResumeCfg(),
	// }
	// engine := core.New(defaultOpts)
	// engine.SetExecuterOptions(executerOpts)

	// workflowLoader, err := parsers.NewLoader(&executerOpts)
	// if err != nil {
	// 	log.Fatalf("Could not create workflow loader: %s\n", err)
	// }
	// executerOpts.WorkflowLoader = workflowLoader

	// configObject, err := config.ReadConfiguration()
	// if err != nil {
	// 	log.Fatalf("Could not read config: %s\n", err)
	// }
	// store, err := loader.New(loader.NewConfig(defaultOpts, configObject, catalog, executerOpts))
	// if err != nil {
	// 	log.Fatalf("Could not create loader client: %s\n", err)
	// }
	// store.Load()
	//
	//input := &inputs.SimpleInputProvider{Inputs: []string{"docs.hackerone.com"}}
	//_ = engine.Execute(store.Templates(), input)
	//engine.WorkPool().Wait() // Wait for the scan to finish
}
