package emailgwefficacy

// RegisterScenarioTestContent makes a scenario's static test message available
// to the EmailGW executor, keyed by message class. Packages that build a
// message's attachment themselves call it from init, so this package never
// has to import them.
func RegisterScenarioTestContent(messageClass string, msg InjectableMessage) {
	scenarioTestContent[messageClass] = msg
}
