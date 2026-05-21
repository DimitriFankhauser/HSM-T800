package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"

	tea "charm.land/bubbletea/v2"
	"github.com/BurntSushi/toml"
	"github.com/ThalesGroup/crypto11"
	"github.com/miekg/pkcs11"
)

func encrypt(m model) (tea.Model, tea.Cmd) {
	return m, tea.Quit
}

func assignConfigObject(m model) (tea.Model, tea.Cmd) {
	var config pkcs11config
	if m.selectedPath != "" {
		//file was picked for config
		if _, err := os.Stat(m.selectedPath); err != nil {
			log.Fatal("Config file is missing: ")
		}
		if _, err := toml.DecodeFile(m.selectedPath, &config); err != nil {
			log.Fatal(err)
		}
	} else {
		config = pkcs11config{
			TokenLabel: configAttributes[0],
			KeyAlias:   configAttributes[1],
			KeyID:      configAttributes[2],
			SoPIN:      configAttributes[3],
			Pin:        configAttributes[4],
			DriverPath: configAttributes[5],
		}
	}
	m.pkcs11config = config
	return m, nil
}

const DUMMY_DRIVERPATH = "/lib64/softhsm/libsofthsm.so"
const DUMMY_TOKENLABEL = "Genesis"
const DUMMY_PIN = "123456789"
const DUMMY_KEYLABEL = "rsaGenesis"
const DUMMY_SLOTINDEX = 11
const DUMMY_ENCRYPTION_STRING = "Hi I really like cats! Meow!"

func formatCount(n uint) string {
	if n == ^uint(0) {
		return "unavailable"
	}
	return fmt.Sprintf("%d", n)
}
func UpdateTokens(m model) (tea.Model, tea.Cmd) {
	m.mode = modes[SELECT_TOKEN]
	m.cursor = 0

	m.tokens = nil
	p := pkcs11.New(DUMMY_DRIVERPATH)
	if err := p.Initialize(); err != nil {
		return nil, tea.Quit
	}
	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, tea.Quit
	}

	var tokens []TokenInfo
	for _, slot := range slots {
		raw, err := p.GetTokenInfo(slot)
		if err != nil {
			return nil, tea.Quit
		}

		tokens = append(tokens, TokenInfo{
			Label:              raw.Label,
			ManufacturerID:     raw.ManufacturerID,
			Model:              raw.Model,
			SerialNumber:       raw.SerialNumber,
			Flags:              raw.Flags,
			MaxSessionCount:    formatCount(raw.MaxSessionCount),
			SessionCount:       formatCount(raw.SessionCount),
			MaxRwSessionCount:  formatCount(raw.MaxRwSessionCount),
			RwSessionCount:     formatCount(raw.RwSessionCount),
			MinPinLen:          raw.MinPinLen,
			MaxPinLen:          raw.MaxPinLen,
			TotalPublicMemory:  formatCount(raw.TotalPublicMemory),
			FreePublicMemory:   formatCount(raw.FreePublicMemory),
			TotalPrivateMemory: formatCount(raw.TotalPrivateMemory),
			FreePrivateMemory:  formatCount(raw.FreePrivateMemory),
			HardwareVersion:    fmt.Sprintf("%d.%d", raw.HardwareVersion.Major, raw.HardwareVersion.Minor),
			FirmwareVersion:    fmt.Sprintf("%d.%d", raw.FirmwareVersion.Major, raw.FirmwareVersion.Minor),
		})
	}

	m.tokens = tokens
	var convertedTokens = []string{}
	for _, token := range m.tokens {
		convertedTokens = append(convertedTokens, (token).String())
	}
	m.mode.options = convertedTokens
	return m, nil
}

func UpdateSymmetricKeys(m model) (tea.Model, tea.Cmd) {
	m.mode = modes[KEY_SELECTED]
	return m, nil

}
func UpdateAsymmetricKeys(m model) (tea.Model, tea.Cmd) {
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       m.pkcs11config.DriverPath,
		TokenLabel: m.pkcs11config.TokenLabel,
		Pin:        m.pkcs11config.Pin,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ctx.Close()

	// --- Asymmetric key pairs ---
	keyPairs, err := ctx.FindAllKeyPairs()
	keys := make([]Key, len(keyPairs))

	if err != nil {
		log.Fatal(err)
	}

	for _, key := range keyPairs {
		attrs, err := ctx.GetAttributes(key, []crypto11.AttributeType{
			crypto11.CkaId,
			crypto11.CkaLabel,
			crypto11.CkaKeyType,
		})
		if err != nil {
			log.Printf("  could not read attributes: %v", err)
			continue
		}
		id := attrs[crypto11.CkaId]
		label := attrs[crypto11.CkaLabel]
		keyType := attrs[crypto11.CkaKeyType]
		key := Key{string(id.Value), string(label.Value), keyTypeToString(keyType.Value)}
		keys = append(keys, key)
	}

	var convertedKeys = []string{}
	for _, key := range keys {
		convertedKeys = append(convertedKeys, key.String())

	}
	m.keys = keys
	m.mode = modes[KEY_SELECTED]
	m.mode.options = convertedKeys
	return m, nil
}
func keyTypeToString(raw []byte) string {
	if len(raw) == 0 {
		return "unknown"
	}
	val := binary.LittleEndian.Uint64(append(raw, make([]byte, 8-len(raw))...))
	if name, ok := ckkNames[val]; ok {
		return name
	}
	return fmt.Sprintf("unknown(0x%X)", val)
}

func UpdateCertificates(m model) (tea.Model, tea.Cmd) {
	return m, nil
}
