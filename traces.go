package main

import (
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/gocql/gocql"
	"github.com/vaughan0/go-ini"
	"gopkg.in/alecthomas/kingpin.v2"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	app      = kingpin.New("cassandra-trace-reporting", "Introspect Cassandra query traces.")
	cqlshrc  = app.Flag("cqlshrc", "Full path to cqlshrc file.").Default("cqlshrc").String()
	hostname = app.Flag("hostname", "Cassandra host.").Default("localhost").String()
	port     = app.Flag("port", "Cassanra port.").Default("9042").Int()

	sessions    = app.Command("sessions", "Query trace sessions.")
	minDuration = sessions.Flag("min-duration", "Minimum query duration (in mircos)").Default("0").Int()

	events     = app.Command("events", "Retrieve events for a trace session.")
	sessId     = events.Flag("id", "Session ID").Required().String()
	onlySource = events.Flag("only-source", "Only show events for a specific source.").String()

	statistics = app.Command("stats", "Report query statistics.")

	// Console colors
	yellow = color.New(color.FgYellow).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
)

type Session struct {
	Id         gocql.UUID
	Command    string
	Duration   int
	Parameters map[string]string
	StartedAt  time.Time
}

type Cqlshrc struct {
	Username string
	Password string
	Ca       string
}

func NewCqlshrc(filename string) (*Cqlshrc, error) {
	config, err := ini.LoadFile(filename)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Unable to parse cqlshrc: %s", err))
	}

	result := &Cqlshrc{}

	if username, ok := config.Get("authentication", "username"); ok {
		result.Username = username
	}
	if password, ok := config.Get("authentication", "password"); ok {
		result.Password = password
	}
	if cert, ok := config.Get("ssl", "certfile"); ok {
		result.Ca = cert
	}

	return result, nil
}

type queryStats struct {
	min, max, cumulative, count int
}

func (q *queryStats) update(duration int) {
	q.cumulative += duration
	q.count += 1
	if duration < q.min {
		q.min = duration
	}
	if duration > q.max {
		q.max = duration
	}
}

func (q *queryStats) avg() int {
	return q.cumulative / q.count
}

func CreateSession(hostname string, port int, cqlshrc string) (*gocql.Session, error) {
	cluster := gocql.NewCluster(hostname)
	cluster.Port = port
	cluster.Keyspace = "system_traces"
	cluster.Consistency = gocql.One
	cluster.HostFilter = gocql.WhiteListHostFilter(hostname)

	rc, err := NewCqlshrc(cqlshrc)
	if err != nil {
		return nil, err
	}

	cluster.Authenticator = gocql.PasswordAuthenticator{
		Username: rc.Username,
		Password: rc.Password,
	}
	cluster.SslOpts = &gocql.SslOptions{
		CaPath: rc.Ca,
	}

	return cluster.CreateSession()
}

func matches(r *regexp.Regexp, input string) map[string]string {
	return mapSubexpNames(r.FindStringSubmatch(input), r.SubexpNames())
}

func mapSubexpNames(m, n []string) map[string]string {
	r := make(map[string]string, len(m))

	// If the expression did not match, `m` will be 0 and no mapping                                                                                                                                                  // will be possible, so just return the empty map.
	if len(m) == 0 {
		return r
	}

	m, n = m[1:], n[1:]
	for i, _ := range n {
		r[n[i]] = m[i]
	}

	return r
}

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	// sessions
	case sessions.FullCommand():
		client, err := CreateSession(*hostname, *port, *cqlshrc)
		if err != nil {
			log.Fatal(err)
		}
		defer client.Close()

		var id gocql.UUID
		var cmd string
		var duration int
		var parameters map[string]string
		var started time.Time
		sessions := make([]Session, 0)
		count := 0

		iter := client.Query("SELECT session_id,command,duration,parameters,started_at FROM system_traces.sessions").Iter()
		for iter.Scan(&id, &cmd, &duration, &parameters, &started) {
			count += 1
			if duration >= *minDuration {
				sessions = append(sessions, Session{id, cmd, duration, parameters, started})
			}
		}

		if err := iter.Close(); err != nil {
			log.Fatal(err)
		}

		sort.Slice(sessions, func(i, j int) bool {
			return sessions[i].Duration > sessions[j].Duration
		})

		for _, s := range sessions {
			fmt.Printf("%s | %8d | %-33s | %s\n", yellow(s.Id), s.Duration, s.StartedAt, cyan(s.Parameters["query"]))
		}

		fmt.Println()
		fmt.Printf("%d matching results (%d total).", len(sessions), count)
		fmt.Println()

	// events
	case events.FullCommand():
		client, err := CreateSession(*hostname, *port, *cqlshrc)
		if err != nil {
			log.Fatal(err)
		}
		defer client.Close()

		// Achtung; This is IPv4-specific!
		unresolved := regexp.MustCompile(` (?P<IP>/[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})`)
		lineNo := 1

		var id time.Time
		var activity string
		var srcHost net.IP
		var srcElapsed int
		var thread string

		iter := client.Query(`SELECT dateOf(event_id),activity,source,source_elapsed,thread FROM system_traces.events WHERE session_id = ?`, *sessId).Iter()
		for iter.Scan(&id, &activity, &srcHost, &srcElapsed, &thread) {
			var srcName string
			// Resolve IPs to hostnames (if possible)
			if names, err := net.LookupAddr(srcHost.String()); err != nil || len(names) < 1 {
				srcName = srcHost.String()
			} else {
				srcName = names[0]
			}

			// Normalize the source
			srcName = strings.TrimRight(srcName, ".")

			// Look for unresolved IP address in the activity string and attempt to resolve it
			if m := matches(unresolved, activity); len(m) > 0 {
				ip := strings.TrimLeft(m["IP"], "/")
				// Best-effort
				if names, err := net.LookupAddr(ip); err == nil || len(names) > 1 {
					activity = strings.Replace(activity, m["IP"], names[0], -1)
				}
			}

			// (Maybe )filter events to those from a single source name/IP.
			if len(*onlySource) < 1 || *onlySource == srcName {
				fmt.Printf("%2d | %-48s | %15s | %8d | %s | %s\n", lineNo, yellow(id), srcName, srcElapsed, thread, cyan(activity))
				lineNo += 1
			}
		}

		if err := iter.Close(); err != nil {
			log.Fatal(err)
		}

	// statistics
	case statistics.FullCommand():
		client, err := CreateSession(*hostname, *port, *cqlshrc)
		if err != nil {
			log.Fatal(err)
		}
		defer client.Close()

		// a map of query strigs and queryStats structs
		queries := make(map[string]*queryStats)

		var duration int
		var parameters map[string]string
		count := 0

		iter := client.Query("SELECT duration,parameters FROM system_traces.sessions").Iter()
		for iter.Scan(&duration, &parameters) {
			if v, exists := queries[parameters["query"]]; !exists {
				queries[parameters["query"]] = &queryStats{duration, duration, duration, 1}
			} else {
				v.update(duration)
			}
			count += 1
		}

		if err := iter.Close(); err != nil {
			log.Fatal(err)
		}

		keys := make([]string, 0, len(queries))

		for k := range queries {
			keys = append(keys, k)
		}

		// Order our list of keys by the corresponding query avg, descending.
		sort.Slice(keys, func(i, j int) bool {
			return queries[keys[i]].avg() > queries[keys[j]].avg()
		})

		fmt.Printf("%9s | %5s | %5s | %5s | %s\n", "Count", "Min", "Max", "Avg", "Query")

		for k := range keys {
			s := queries[keys[k]]
			fmt.Printf("%9d | %5d | %5d | %5d | %s\n", s.count, s.min, s.max, s.avg(), cyan(keys[k]))
		}

		fmt.Printf("\n%d unique queries (%d total sessions analyzed).\n", len(queries), count)
	}
}
