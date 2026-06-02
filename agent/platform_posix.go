//go:build linux || darwin

package main

func registerPlatformFlags()               {}
func platformHandleFlags() bool            { return false }
func platformPreStart()                    {}
func platformPrintBannerExtras(_ Identity) {}
