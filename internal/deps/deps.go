package deps
import (
	_ "github.com/jackc/pgx/v5/pgxpool"
	_ "golang.org/x/crypto/bcrypt"
	_ "golang.org/x/net/idna"
	_ "github.com/colinmarc/cdb"
	_ "github.com/dnstap/golang-dnstap"
	_ "github.com/farsightsec/golang-framestream"
	_ "github.com/miekg/dns"
)
