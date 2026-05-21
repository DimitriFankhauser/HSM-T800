package main

const (
	STARTMODE                 = 0
	READ_CONFIG_FILE          = 1
	READ_CONFIG_USER          = 2
	CONFIRM_SELECTED_CONFIG   = 3
	CONFIG_CONFIRMED          = 4
	SELECT_TOKEN              = 5
	CREATE_TOKEN              = 6
	OPERATE_ON_TOKEN          = 8
	SELECT_EXISTING_KEY       = 9
	KEY_SELECTED              = 10
	GET_ENCRYPTABLE_FILE      = 11
	ENCRYPT                   = 12
	ENCRYPTION_OPERATION_DONE = 13
	CHOOSE_MECHANISM          = 14
	CERT_SELECTED             = 15
	USE_KEY                   = 16
	USE_KEY_PROMPT            = 17
	USE_KEY_FILE              = 18
)

type mode struct {
	modeNum int
	title   string
	options []string
}

var modes = map[int]mode{
	STARTMODE:               {modeNum: STARTMODE, title: "Welcome to HSM-Helper T800", options: []string{"ENTER CONFIG MANUALLY", "READ CONFIG FROM FILE"}},
	READ_CONFIG_FILE:        {modeNum: READ_CONFIG_FILE, title: "Let's read a config file", options: []string{"file A", "file B"}},
	READ_CONFIG_USER:        {modeNum: READ_CONFIG_USER, title: "enter your config one by one", options: []string{"TokenLabel", "KeyAlias", "KeyID", "SoPin", "Pin", "DriverPath"}},
	CONFIRM_SELECTED_CONFIG: {modeNum: CONFIRM_SELECTED_CONFIG, title: "CONFIRM?", options: []string{"YES", "NO"}},
	CONFIG_CONFIRMED:        {modeNum: CONFIG_CONFIRMED, title: "What would you like to do?", options: []string{"Work with existing", "Create a new token"}},
	SELECT_TOKEN:            {modeNum: SELECT_TOKEN, title: "Select a token"},
	OPERATE_ON_TOKEN: {modeNum: OPERATE_ON_TOKEN, title: "What would you like to do with this token?", options: []string{
		"Create a Key",
		"Show Asymmetric Keys",
		"Show Symmetric Keys",
		"Show Certificates",
	}},
	SELECT_EXISTING_KEY:       {modeNum: SELECT_EXISTING_KEY, title: "Select a key"},
	KEY_SELECTED:              {modeNum: KEY_SELECTED, title: "Let's do some encryption, shall we?"},
	GET_ENCRYPTABLE_FILE:      {modeNum: GET_ENCRYPTABLE_FILE, title: "Select a file to encrypt/hash"},
	ENCRYPT:                   {modeNum: ENCRYPT, title: "ENCRYPTING"},
	ENCRYPTION_OPERATION_DONE: {modeNum: ENCRYPTION_OPERATION_DONE, title: "ENCRYPTION OPERATION DONE"},
	CHOOSE_MECHANISM:          {modeNum: CHOOSE_MECHANISM, title: "Choose a mechanism"},
	CERT_SELECTED:             {modeNum: CERT_SELECTED},
	USE_KEY:                   {modeNum: USE_KEY, title: "How would you like to use this key", options: []string{"prompt input", "select file"}},
	USE_KEY_PROMPT:            {modeNum: USE_KEY_PROMPT},
	USE_KEY_FILE:              {modeNum: USE_KEY_FILE},
}
