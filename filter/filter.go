package filter

import (
	"bufio"
	"fmt"
	"github.com/rstms/rspamd-classes/classes"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

/*********************************************************************************************

 smtpd-filter-spamclass

 add a header: 'X-Spam-Class: SPAMCLASS'
 based on threshold levels compared with rspamd's X-Spam-Score header

 Default class threshold levels:

 ham:		spam_score < HAM_THRESHOLD
 possible:	HAM_THRESHOLD <= spam_score < POSSIBLE_THRESHOLD
 probable:	POSSIBLE_THRESHOLD <= spam_score < PROBABLE_THRESHOLD
 spam:		spam_score >= PROBABLE_THRESHOLD

 class names and thresholds are configurable per recipient email address
 using a JSON file with the following format:

{
    "username@example.org": [
	{ "name": "ham", "score": 0 },
	{ "name": "possible", "score": 3 },
	{ "name": "probable", "score": 10 },
	{ "name": "spam", "score": 999 }
    ],
    "othername@example.org": [
	{ "name": "not_spam", "score": 0 },
	{ "name": "suspected_spam", "score": 10 },
	{ "name": "is_spam", "score": 999 }
    ]
}

The final threshold value is set to float32-max automatically; 999 is a placeholder

*********************************************************************************************/

const Version = "0.0.4"

const DEFAULT_CLASS_CONFIG_FILE = "/etc/mail/filter_rspamd_classes.json"

var EMAIL_ADDRESS_BRACKET_PATTERN = regexp.MustCompile(`^.*<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>.*$`)
var EMAIL_ADDRESS_PATTERN = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

const FID_NAME = 4
const FID_SID = 5
const FID_TOKEN = 6

var Verbose bool

type Message struct {
	Id           string
	From         []string
	To           []string
	EnvelopeTo   []string
	EnvelopeFrom []string
	State        string
	InHeader     bool
	SpamScore    float32
	SpamScoreSet bool
}

func NewMessage(mid string) *Message {
	return &Message{
		Id:           mid,
		To:           []string{},
		From:         []string{},
		EnvelopeTo:   []string{},
		EnvelopeFrom: []string{},
		State:        "init",
		InHeader:     true,
	}
}

type Session struct {
	Id             string
	Messages       map[string]*Message
	RDNS           string
	Confirmed      bool
	Remote         string
	Local          string
	AuthorizedUser string
	DataMessage    string
}

func NewSession(sid, rdns string, confirmed bool, remote, local string) *Session {
	return &Session{
		Id:        sid,
		RDNS:      rdns,
		Confirmed: confirmed,
		Remote:    remote,
		Local:     local,
		Messages:  make(map[string]*Message),
	}
}

type Callback struct {
	Handler func(string, []string)
	Args    int
}

type Filter struct {
	Name      string
	Sessions  map[string]*Session
	Protocol  string
	Classes   *classes.SpamClasses
	Subsystem string
	reports   []string
	filters   []string
	verbose   bool
	input     *bufio.Scanner
	output    io.Writer
}

func NewFilter(reader io.Reader, writer io.Writer) *Filter {
	ViperSetDefault("class_config_file", DEFAULT_CLASS_CONFIG_FILE)
	executable, err := os.Executable()
	if err != nil {
		log.Fatal(Fatal(err))
	}
	f := Filter{
		Name:     filepath.Base(executable),
		verbose:  ViperGetBool("verbose"),
		Sessions: make(map[string]*Session),
		input:    bufio.NewScanner(reader),
		output:   writer,
		reports: []string{
			"link-connect",
			"link-disconnect",
			"link-auth",
			"tx-reset",
			"tx-begin",
			"tx-mail",
			"tx-rcpt",
			"tx-data",
			"tx-commit",
			"tx-rollback",
		},
		filters: []string{
			"data-line",
		},
	}
	f.Classes = f.readClasses(ViperGetString("class_config_file"))
	return &f
}

func (f *Filter) Config() {
	for f.input.Scan() {
		line := f.input.Text()
		if f.verbose {
			log.Printf("%s config: %s\n", f.Name, line)
		}
		fields := strings.Split(line, "|")
		if len(fields) < 2 {
			log.Fatal(Fatalf("unexpected config line: %s", line))
		}
		switch fields[1] {
		case "protocol":
			f.Protocol = fields[2]
		case "subsystem":
			f.Subsystem = fields[2]
		case "ready":
			return
		}
	}
	err := f.input.Err()
	if err != nil {
		log.Fatal(Fatal(err))
	}
	log.Fatal(Fatalf("config failure"))
}

func (f *Filter) Register() {
	for _, name := range f.reports {
		line := fmt.Sprintf("register|report|%s|%s", f.Subsystem, name)
		log.Printf("%s.Register: %s\n", f.Name, line)
		_, err := fmt.Fprintf(f.output, "%s\n", line)
		if err != nil {
			log.Fatal(Fatal(err))
		}
	}
	for _, name := range f.filters {
		line := fmt.Sprintf("register|filter|%s|%s", f.Subsystem, name)
		if f.verbose {
			log.Printf("%s.Register: %s\n", f.Name, line)
		}
		_, err := fmt.Fprintf(f.output, "%s\n", line)
		if err != nil {
			log.Fatal(Fatal(err))
		}
	}
	line := fmt.Sprintf("register|ready")
	if f.verbose {
		log.Printf("%s.Register: %s\n", f.Name, line)
	}
	_, err := fmt.Fprintf(f.output, "%s\n", line)
	if err != nil {
		log.Fatal(Fatal(err))
	}

}

func requireArgs(name string, atoms []string, count int) {
	if len(atoms) < count {
		log.Fatal(Fatalf("%s: expected %d args, got '%v'", name, count, atoms))
	}
}

func lastAtom(line string, atoms []string, field int) string {
	var index int
	for i := 0; i < field; i++ {
		index += (len(atoms[i]) + 1)
	}
	ret := line[index:]
	return ret
}

func (f *Filter) Run() {
	log.Printf("Starting %s v%s\n", f.Name, Version)
	if f.verbose {
		log.Printf("%s: pid=%d uid=%d gid=%d\n", f.Name, os.Getpid(), os.Getuid(), os.Getgid())
		log.Printf("%s: %s\n", f.Name, FormatJSON(f))
	}
	f.Config()
	f.Register()
	for f.input.Scan() {
		line := f.input.Text()
		atoms := strings.Split(line, "|")
		if len(atoms) < 6 {
			log.Fatal(Fatalf("missing atoms: %s", line))
		}
		switch atoms[0] {
		case "report":
			name := atoms[FID_NAME]
			sid := atoms[FID_SID]
			switch name {
			case "link-connect":
				requireArgs(name, atoms, 10)
				f.linkConnect(name, sid, atoms[6], atoms[7], atoms[8], atoms[9])
			case "link-disconnect":
				f.linkDisconnect(name, sid)
			case "link-auth":
				requireArgs(name, atoms, 8)
				f.linkAuth(name, sid, atoms[6], atoms[7])
			case "tx-reset":
				requireArgs(name, atoms, 7)
				f.txReset(name, sid, atoms[6])
			case "tx-begin":
				requireArgs(name, atoms, 7)
				f.txBegin(name, sid, atoms[6])
			case "tx-mail":
				requireArgs(name, atoms, 9)
				f.txMail(name, sid, atoms[6], atoms[7], atoms[8])
			case "tx-rcpt":
				requireArgs(name, atoms, 9)
				f.txRcpt(name, sid, atoms[6], atoms[7], atoms[8])
			case "tx-data":
				requireArgs(name, atoms, 8)
				f.txData(name, sid, atoms[6], atoms[7])
			case "tx-commit":
				requireArgs(name, atoms, 8)
				f.txCommit(name, sid, atoms[6], atoms[7])
			case "tx-rollback":
				requireArgs(name, atoms, 7)
				f.txRollback(name, sid, atoms[6])
			}
		case "filter":
			phase := atoms[FID_NAME]
			sid := atoms[FID_SID]
			token := atoms[FID_TOKEN]
			switch phase {
			case "data-line":
				requireArgs(phase, atoms, 8)
				f.dataLine(phase, sid, token, lastAtom(line, atoms, 7))
			}
		default:
			log.Fatal(Fatalf("unexpected input: %v", line))
		}
	}
	err := f.input.Err()
	if err != nil {
		log.Fatal(Fatalf("input failed with: %v", err))
	}
	log.Printf("%s: unexpected EOF on stdin\n", f.Name)
}

func (f *Filter) getSession(name, sid string) *Session {
	session, ok := f.Sessions[sid]
	if !ok {
		log.Fatal(Fatalf("%s: unknown session: %s\n", name, sid))
	}
	return session
}

func (f *Filter) getSessionMessage(name, sid, mid string) (*Session, *Message) {
	session := f.getSession(name, sid)
	message, ok := session.Messages[mid]
	if !ok {
		log.Fatal(Fatalf("%s: session %s unknown messageId: %s\n", name, sid, mid))
	}
	return session, message
}

func parseArgs(name string, args []string) (string, string, string, string) {
	for len(args) < 4 {
		args = append(args, "")
	}
	return args[0], args[1], args[2], args[3]
}

func (f *Filter) linkConnect(name, sid, rdns, confirmed, src, dst string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s rdns=%s confirmed=%s src=%s dst=%s\n", f.Name, name, sid, rdns, confirmed, src, dst)
	}
	_, ok := f.Sessions[sid]
	if ok {
		log.Fatal(Fatalf("%s.%s: existing session: %s", f.Name, name, sid))
	}
	f.Sessions[sid] = NewSession(sid, rdns, confirmed == "pass", src, dst)
}

func (f *Filter) linkDisconnect(name, sid string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s\n", f.Name, name, sid)
	}
	f.getSession(name, sid)
	delete(f.Sessions, sid)
}

func (f *Filter) linkAuth(name, sid, result, username string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s result=%s username=%s\n", f.Name, name, sid, result, username)
	}
	session := f.getSession(name, sid)
	if result == "pass" {
		session.AuthorizedUser = username
	}
}

func (f *Filter) txReset(name, sid, mid string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s\n", f.Name, name, sid, mid)
	}
	session, _ := f.getSessionMessage(name, sid, mid)
	session.Messages[mid] = NewMessage(mid)
}

func (f *Filter) txBegin(name, sid, mid string) {
	if f.verbose {
		log.Printf("%s %s: session=%s message=%s\n", f.Name, name, sid, mid)
	}
	session := f.getSession(name, sid)
	_, ok := session.Messages[mid]
	if ok {
		log.Fatal(Fatalf("%s: in session %s for existing message %s", name, sid, mid))
	}
	session.Messages[mid] = NewMessage(mid)
}

func (f *Filter) txMail(name, sid, mid, result, address string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s\n", f.Name, name, sid, mid)
	}
	_, message := f.getSessionMessage(name, sid, mid)
	if result == "ok" {
		address, ok := f.parseEmailAddress(address)
		if ok {
			message.EnvelopeFrom = append(message.EnvelopeFrom, address)
		} else {
			log.Printf("%s.%s: WARNING failed parsing envelopeFrom: %s\n", f.Name, name, address)
		}
	}
}

func (f *Filter) txRcpt(name, sid, mid, result, address string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s result=%s address=%s\n", f.Name, name, sid, mid, result, address)
	}
	_, message := f.getSessionMessage(name, sid, mid)
	if result == "ok" {
		address, ok := f.parseEmailAddress(address)
		if ok {
			message.EnvelopeTo = append(message.EnvelopeTo, address)
		} else {
			log.Printf("%s.%s: WARNING failed parsing envelopeTo: %s\n", f.Name, name, address)
		}

	}
}

func (f *Filter) txData(name, sid, mid, result string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s\n", f.Name, name, sid, mid)
	}
	session, message := f.getSessionMessage(name, sid, mid)
	if result == "ok" {
		session.DataMessage = mid
		message.State = "data"
		message.InHeader = true
	}
}

func (f *Filter) txCommit(name, sid, mid, size string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s size=%s\n", f.Name, name, sid, mid, size)
	}
	_, message := f.getSessionMessage(name, sid, mid)
	message.State = "commit"
}

func (f *Filter) txRollback(name, sid, mid string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s message=%s\n", f.Name, name, sid, mid)
	}
	_, message := f.getSessionMessage(name, sid, mid)
	message.State = "rollback"
}

func (f *Filter) sessionTimeout(name, sid string) {
	if f.verbose {
		log.Printf("%s.%s: session=%s\n", f.Name, name, sid)
	}
	f.getSession(name, sid)
	delete(f.Sessions, sid)
}

func (f *Filter) dataLine(name, sid, token, line string) {
	if f.verbose {
		log.Printf("%s.%s: sid=%s token=%s line=%s\n", f.Name, name, sid, token, line)
	}
	lines := []string{line}
	session := f.getSession(name, sid)
	_, message := f.getSessionMessage(name, sid, session.DataMessage)
	if message.InHeader {
		if strings.TrimSpace(line) == "" {
			message.InHeader = false
		}
		lines = f.filterDataLine(name, session, message, line)
	}
	for _, oline := range lines {
		_, err := fmt.Fprintf(f.output, "filter-dataline|%s|%s|%s\n", sid, token, oline)
		if err != nil {
			log.Fatal(Fatal(err))
		}
	}
}

func (f *Filter) parseSpamScore(line string) float32 {
	fields := strings.Split(line, " ")
	if len(fields) < 2 {
		log.Fatal(Fatalf("spam score parse failed"))
	}
	score, err := strconv.ParseFloat(fields[1], 32)
	if err != nil {
		log.Fatal(Fatal(err))
	}
	return float32(score)
}

func (f *Filter) parseEmailAddress(address string) (string, bool) {
	parsed := strings.TrimSpace(address)
	groups := EMAIL_ADDRESS_BRACKET_PATTERN.FindStringSubmatch(parsed)
	if len(groups) == 2 {
		parsed = groups[1]
	}
	if !EMAIL_ADDRESS_PATTERN.MatchString(parsed) {
		return "", false
	}
	return parsed, true
}

func (f *Filter) readClasses(filename string) *classes.SpamClasses {
	spamClasses, err := classes.New(filename)
	if err != nil {
		log.Fatal(Fatalf("SpamClasses config error: %v\n", err))
	}
	if f.verbose {
		log.Printf("%s: read classes from %s\n", f.Name, filename)
	}
	return spamClasses
}

func (f *Filter) filterDataLine(name string, session *Session, message *Message, line string) []string {

	output := []string{line}
	switch {

	case strings.HasPrefix(line, "X-Spam-Score: "):
		message.SpamScore = f.parseSpamScore(line)
		message.SpamScoreSet = true

	case strings.HasPrefix(line, "X-Spam: "):
		// remove original 'X-Spam' header
		return []string{}

	case strings.HasPrefix(line, "X-Spam-Class: "):
		// remove original 'X-Spam-Class' header
		return []string{}

	case strings.HasPrefix(line, "To: "):
		_, value, ok := strings.Cut(line, " ")
		if !ok {
			log.Printf("%s.%s: missing address in: %s\n", f.Name, name, line)
		}
		address, ok := f.parseEmailAddress(value)
		if !ok {
			log.Printf("%s.%s: failed parsing From address: %s\n", f.Name, name, line)
			return output
		}
		message.To = append(message.To, address)

	case strings.HasPrefix(line, "From: "):
		_, value, ok := strings.Cut(line, " ")
		if !ok {
			log.Printf("%s.%s: missing address in: %s\n", f.Name, name, line)
		}
		address, ok := f.parseEmailAddress(value)
		if !ok {
			log.Printf("%s.%s: failed parsing From address: %s\n", f.Name, name, line)
			return output
		}
		message.From = append(message.From, address)

	case strings.TrimSpace(line) == "":

		if f.verbose {
			log.Printf("%s.%s: generating headers for message: %s\n", f.Name, name, FormatJSON(message))
		}

		// end of headers reached, generate X-Spam-Class, X-Spam headers
		if !message.SpamScoreSet {
			log.Printf("%s.%s: X-Spam-Score header not found\n", f.Name, name)
			return output
		}

		if len(message.To) < 1 {
			log.Printf("%s.%s: missing To address'\n", f.Name, name)
			return output
		}

		if len(message.EnvelopeTo) < 1 {
			log.Printf("%s.%s: missing EnvelopeTo address'\n", f.Name, name)
			return output
		}

		if message.EnvelopeTo[0] != message.To[0] {
			log.Printf("%s.%s: WARNING envelopeTo (%s) mismatches initial To (%s)\n", f.Name, name, message.EnvelopeTo, message.To[0])
		}

		name, domain, found := strings.Cut(message.To[0], "@")
		if !found {
			log.Printf("%s.%s: '@' not found in To address: %v\n", f.Name, name, message.To)
			return output
		}

		// strip off possible plus-alias
		name, _, _ = strings.Cut(name, "+")
		address := fmt.Sprintf("%s@%s", name, domain)

		// prepend generated X-Spam-Class header line to output
		spamClass := f.Classes.GetClass([]string{address}, message.SpamScore)
		if f.verbose {
			log.Printf("%s.%s: GetClass(%v, %v) returned %s\n", f.Name, name, []string{address}, message.SpamScore, FormatJSON(spamClass))
		}
		if spamClass != "" {
			output = append([]string{"X-Spam-Class: " + spamClass}, output...)
		}

		// generate new X-Spam header
		spamState := "no"
		if spamClass == "spam" {
			spamState = "yes"
		}

		// prepend generated X-Spam header line to output
		output = append([]string{"X-Spam: " + spamState}, output...)
		log.Printf("%s.%s: address=%s score=%v class='%s' spam=%v\n", f.Name, name, address, message.SpamScore, spamClass, spamState)
	}
	return output
}
