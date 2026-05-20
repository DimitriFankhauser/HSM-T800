package main

import (
	"log"
	"os"
	"strings"

	"github.com/ThalesGroup/crypto11"
)

// Source - https://stackoverflow.com/a/22467409
// Posted by user3431012, modified by community. See post 'Timeline' for change history
// Retrieved 2026-05-20, License - CC BY-SA 4.0

func checkFileExists(filePath string) bool {
	if !strings.HasSuffix(filePath, ".so") {
		return false
	}

	_, error := os.Stat(filePath)
	if error != nil {
		return false
	}
	return true
}

func initializeCtx(m *model) {
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       m.pathToSo,
		TokenLabel: m.tokenLabel,
		Pin:        m.pin,
	})
	if err != nil {
		ctx = nil
		log.Fatal(err)
	} else {
		m.ctx = ctx
	}
}

func getKeyPairs(ctx *crypto11.Context) []crypto11.Signer {
	if ctx == nil {
		return nil
	} else {
		keyPairs, err := ctx.FindAllKeyPairs()
		if err != nil {
			log.Fatalf("FindAllKeyPairs: %v", err)
		}
		return keyPairs
	}

}
