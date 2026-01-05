package filter

import (
	"bufio"
	"github.com/stretchr/testify/require"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilter(t *testing.T) {

	Init("smtpd-filter-addheader", Version, filepath.Join("testdata", "config.yaml"))
	filterIn, testOut, err := os.Pipe()
	require.Nil(t, err)
	testIn, filterOut, err := os.Pipe()
	require.Nil(t, err)
	f := NewFilter(filterIn, filterOut)
	go f.Run()
	for _, line := range initLines {
		_, err := testOut.WriteString(line + "\n")
		require.Nil(t, err)
		log.Printf("TEST_SENT: %s\n", line)
	}

	scanner := bufio.NewScanner(testIn)
	for registered := false; !registered; {
		require.True(t, scanner.Scan())
		line := scanner.Text()
		log.Printf("TEST_GOT: %s\n", line)
		if line == "register|ready" {
			registered = true
		}
	}

	for _, line := range messageLines {
		_, err := testOut.WriteString(line + "\n")
		require.Nil(t, err)
		log.Printf("TEST_SENT: %s\n", line)
	}

	filteredMessage := []string{}
	for done := false; !done; {
		require.True(t, scanner.Scan())
		line := scanner.Text()
		line = line[:len(line)]
		log.Printf("TEST_GOT: %s\n", line)
		if strings.HasPrefix(line, "filter-dataline|") {
			filteredMessage = append(filteredMessage, line)
			if strings.HasSuffix(line, "|.") {
				done = true
			}
		}
	}
	testOut.Close()
	testIn.Close()
	filterIn.Close()
	filterOut.Close()
	log.Println(FormatJSON(filteredMessage))
}

var initLines []string = []string{
	"config|smtpd-version|7.7.0",
	"config|protocol|0.7",
	"config|smtp-session-timeout|300",
	"config|subsystem|smtp-in",
	"config|ready",
}

var messageLines []string = []string{

	"report|0.7|0000000000.000000|smtp-in|link-connect|deadbeef|sendhost.example.org|pass|1.2.3.4:11223|5.6.7.8:25",
	"report|0.7|0000000000.000000|smtp-in|link-auth|deadbeef|pass|authuser",
	"report|0.7|0000000000.000000|smtp-in|tx-begin|deadbeef|cafebabe",
	"report|0.7|0000000000.000000|smtp-in|tx-mail|deadbeef|cafebabe|ok|fromuser@example.org",
	"report|0.7|0000000000.000000|smtp-in|tx-rcpt|deadbeef|cafebabe|ok|touser@localdomain.ext",
	"report|0.7|0000000000.000000|smtp-in|tx-data|deadbeef|cafebabe|ok",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|Received: from localhost",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|    by mailbox.rstms.net with LMTP",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|    id SYMsDtUVXGkCNQAA8o/S4",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|    (envelope-from <bounce+403268.63af5d-rumble=rstms.net@mg-d0.substack.com>)",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|    for <mkrueger>; Mon, 05 Jan 2026 12:49:41 -0700",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|X-Spam: no",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|X-Spam-Score: 1.155 / 100",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|X-Spam-Class: original",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|X-Spam-Status: Yes, score=1.155 required=100.000",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|    tests=[ARC_NA=0.000, ASN=0.000, DKIM_TRACE=0.000",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|    DMARC_POLICY_ALLOW=00.500,",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|    ZERO_FONT=0.300]",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|To: touser@localdomain.ext",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|From: fromuser@example.org",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|Subject: filter test message",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|first message body line",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|second message body line with embedded | character",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|third and last message body line",
	"filter|0.7|0000000000.000000|smtp-in|data-line|deadbeef|baadf00d|.",
	"report|0.7|0000000000.000000|smtp-in|tx-commit|deadbeef|cafebabe|1234",
	"report|0.7|0000000000.000000|smtp-in|link-disconnect|deadbeef",
}
