Cassandra Query Trace Reporting
===============================

Convenience utility for querying Cassandra trace session and event
information.  Written in Go because that is what all of the Cool Kids
are using these days.

You need some traces to look at, so maybe...

    $ nodetool settraceprobability 0.1  # Trace 10% of all queries

Invoke `cassandra-trace-reporting` to view stored trace sessions and/or events.

    usage: cassandra-trace-reporting [<flags>] <command> [<args> ...]
    
    Introspect Cassandra query traces.
    
    Flags:
      --help                  Show context-sensitive help (also try --help-long and --help-man).
      --cqlshrc="cqlshrc"     Full path to cqlshrc file.
      --hostname="localhost"  Cassandra host.
      --port=9042             Cassanra port.
    
    Commands:
      help [<command>...]
        Show help.
    
    
      sessions [<flags>]
        Query trace sessions.
    
        --min-duration=0  Minimum query duration (in mircos)
    
      events --id=ID [<flags>]
        Retrieve events for a trace session.
    
        --id=ID                    Session ID
        --only-source=ONLY-SOURCE  Only show events for a specific source.
    
      stats
        Report query statistics.
    

Shell completion
----------------

### For bash

    $ eval "$(traces --completion-script-bash)"
    
### For zsh

    $ eval "$(traces --completion-script-zsh)"


