webauthn-gate:
	go build -o webauthn-gate . 
webauthn-gate.exe:
	env GOOS=windows GOARCH=amd64 go build -o webauthn-gate.exe .
webauthn-gate-arm64-linux:
	env GOOS=linux GOARCH=arm64 go build -o webauthn-gate-arm64-linux


