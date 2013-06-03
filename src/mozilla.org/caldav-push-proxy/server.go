package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/garyburd/redigo/redis"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type ServerConfig struct {
	Hostname      string `json:"hostname"`
	Port          string `json:"port"`
	RedisHostname string `json:"redisHostname"`
	RedisPort     string `json:"redisPort"`
	UseTLS        bool   `json:"useTLS"`
	CertFilename  string `json:"certFilename"`
	KeyFilename   string `json:"keyFilename"`
}

var gServerConfig ServerConfig

func readConfig() {

	var data []byte
	var err error

	data, err = ioutil.ReadFile("config.json")
	if err != nil {
		log.Println("Not configured.  Could not find config.json")
		os.Exit(-1)
	}

	err = json.Unmarshal(data, &gServerConfig)
	if err != nil {
		log.Println("Could not unmarshal config.json", err)
		os.Exit(-1)
		return
	}
}

type MultiStatusResponse struct {
	XMLName  xml.Name `xml:"multistatus"`
	Response struct {
		Propstat struct {
			Prop struct {
				Getctag string `xml:"getctag"`
			} `xml:"prop"`
		} `xml:"propstat"`
	} `xml:"response"`
}

var gRedis redis.Conn
var pushClient http.Client
var calendarClient http.Client

func notifyEndpoint(endpoint string) {
	log.Println("Notifying", endpoint)
	body := fmt.Sprintf("version=%d", uint64(time.Now().Unix()))
	r, err := http.NewRequest("PUT", endpoint, strings.NewReader(body))
	if err != nil {
		log.Println(err)
		return
	}

	r.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}

	_, err = pushClient.Do(r)
	if err != nil {
		log.Println(err)
		return
	}
}

// Username uniquely identifies a user.
// A User has 2 endpoints, one for updates and one for errors.
// A User also has calendars
// Nothing stops the same device from having multiple users.
type Username string // caldav-user:Username::Domain

func username(username string, domain string) Username {
	return Username(fmt.Sprintf("caldav-user::%s::%s", username, domain))
}

// Mapping from Username -> password.
// or Username -> oauth access_token
// Should be kept strictly in memory and not logged.
type C struct {
	Token   string
	IsOauth bool
}
type Credentials map[Username]C

var gCredentials Credentials

type AccountModel struct {
	Domain   string `json:"domain"`
	User     string `json:"user"`
	Password string `json:"password"`
	Oauth    struct {
		AccessToken string `json:"access_token"`
	} `json:"oauth"`
	UpdateEndpoint string `json:"updateEndpoint"`
	ErrorEndpoint  string `json:"errorEndpoint"`
}

type RemoteCalendarModel struct {
	Url       string `json:"url"`
	SyncToken string `json:"syncToken"` // Actually http://calendarserver.org/ns/getctag.
}

type CalendarModel struct {
	Remote RemoteCalendarModel `json:"remote"`
}

type RegistrationRequest struct {
	User      AccountModel    `json:"user"`
	Calendars []CalendarModel `json:"calendars"`
}

func notifyErrorToUser(u Username) {
	errorEndpoint, err := redis.String(gRedis.Do("HGET", u, "errorEndpoint"))
	if err == nil {
		notifyEndpoint(errorEndpoint)
	} else {
		log.Println("Error %s notifying Error to User %s", err, u)
	}
}

/*
* When the server shuts down, it loses the credentials of all users.
* It uses the known error endpoints to request clients to tell it the passwords again.
 */
func askClientsToRegisterAgain() {
	users, err := redis.Strings(gRedis.Do("KEYS", "caldav-users:*"))
	if err == nil {
		for _, user := range users {
			notifyErrorToUser(Username(user))
		}
	}
}

func propfind(account AccountModel, url string) (string, error) {
	body := `<?xml version="1.0" encoding="utf-8" ?>
    <D:propfind xmlns:D="DAV:">
      <D:prop xmlns:CS="http://calendarserver.org/ns/">
        <CS:getctag/>
      </D:prop>
    </D:propfind>`

	r, err := http.NewRequest("PROPFIND", url, strings.NewReader(body))
	if err != nil {
		return "", err
	}

	if account.Oauth.AccessToken != "" {
		r.Header["Authorization"] = []string{fmt.Sprintf("Bearer %s", account.Oauth.AccessToken)}
	} else {
		r.SetBasicAuth(account.User, account.Password)
	}
	r.Header["Content-Type"] = []string{"application/xml"}
	r.Header["Depth"] = []string{"0"}
	resp, reqErr := calendarClient.Do(r)
	if reqErr != nil {
		return "", reqErr
	}

	defer resp.Body.Close()
	decoder := xml.NewDecoder(resp.Body)
	v := MultiStatusResponse{}
	parseErr := decoder.Decode(&v)
	if parseErr != nil {
		return "", parseErr
	}

	return v.Response.Propstat.Prop.Getctag, nil
}

// Redis storage is as a hash with base key the username.
// Each hash entry is:
// updateEndpoint -> string
// errorEndpoint -> string
// <cal1 url> -> ctag
// <cal2 url> -> ctag
// ...
func redisHashFromRequest(req *RegistrationRequest) []interface{} {
	var arr []interface{}

	arr = append(arr, "updateEndpoint", req.User.UpdateEndpoint)
	arr = append(arr, "errorEndpoint", req.User.ErrorEndpoint)

	for _, calendar := range req.Calendars {
		arr = append(arr, calendar.Remote.Url, calendar.Remote.SyncToken)
	}

	return arr
}

func mapFromRedisHash(redisHash []string) map[string]string {
	if len(redisHash)%2 != 0 {
		log.Fatal("Invalid redisHash (odd length) %s", redisHash)
	}

	entries := make(map[string]string)
	for i := range redisHash {
		if i%2 != 0 {
			continue
		}

		entries[redisHash[i]] = redisHash[i+1]
	}

	return entries
}

func registerHandler(resp http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		resp.WriteHeader(http.StatusMethodNotAllowed)
		resp.Write([]byte("Not a post request"))
		log.Println("Not a post request")
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte("Could not access body of request"))
		log.Println("Could not access body")
		return
	}

	request := new(RegistrationRequest)
	err = json.Unmarshal(body, request)

	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte("Could not unmarshal body, "))
		log.Println(err)
		return
	}

	username := username(request.User.User, request.User.Domain)
	if request.User.Oauth.AccessToken != "" {
		gCredentials[username] = C{request.User.Oauth.AccessToken, true}
	} else {
		gCredentials[username] = C{request.User.Password, false}
	}

	redisHash := redisHashFromRequest(request)
	if len(redisHash)%2 != 0 {
		log.Fatal("Invalid hash from request %s", redisHash)
	}

	var args []interface{}
	args = append(args, string(username))
	args = append(args, redisHash...)
	if _, saveErr := gRedis.Do("HMSET", args...); saveErr != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte("Could not save to database"))
		log.Println("Error saving request")
	}
}

func checkCalendars(account AccountModel, calendars map[string]string) {
	username := username(account.User, account.Domain)
	usernameParts := strings.Split(string(username), "::")
	if len(usernameParts) != 3 {
		log.Panic("Bad username %s", usernameParts)
	}

	anyCalendarChanged := false
	for calendar, syncToken := range calendars {
		calendarUrl := fmt.Sprintf("%s%s", usernameParts[2], calendar)

		newSyncToken, err := propfind(account, calendarUrl)
		if err != nil {
			log.Println("Error propfinding", err)
			notifyEndpoint(account.ErrorEndpoint)
			gRedis.Do("DEL", username)
			// If any calendar fails, no point continuing
			return
		}

		if newSyncToken != syncToken {
			log.Println(calendarUrl, "changed")
			anyCalendarChanged = true
			// update our cache
			if _, saveErr := gRedis.Do("HSET", username, calendar, newSyncToken); saveErr != nil {
				log.Println("Error updating syncToken to", newSyncToken, "for", username, calendarUrl)
			}
		}
	}

	if anyCalendarChanged {
		notifyEndpoint(account.UpdateEndpoint)
	}
}

// Of course this is not the right way to do constant time polling.
func pollCalendars() {
	for {
		time.Sleep(15 * time.Second) // FIXME Minute
		entries, err := redis.Strings(gRedis.Do("KEYS", "caldav-user:*"))
		log.Println("Polling", len(entries), "users.")
		if err != nil {
			log.Println("Error fetching keys")
			continue
		}

		for _, entry := range entries {
			redisHash, getAllErr := redis.Strings(gRedis.Do("HGETALL", entry))
			if getAllErr != nil {
				log.Println("Could not get hash entry for %s", entry)
				continue
			}

			hash := mapFromRedisHash(redisHash)
			updateEndpoint := hash["updateEndpoint"]
			errorEndpoint := hash["errorEndpoint"]
			delete(hash, "updateEndpoint")
			delete(hash, "errorEndpoint")

			passwd, found := gCredentials[Username(entry)]
			if !found {
				log.Println("Password not found for", entry)
				notifyEndpoint(errorEndpoint)
				gRedis.Do("DEL", entry)
				delete(gCredentials, Username(entry))
				continue
			}

			usernameParts := strings.Split(entry, "::")
			if len(usernameParts) != 3 {
				log.Panic("Non len 3 %s", usernameParts)
			}
			x := AccountModel{
				User:           usernameParts[1],
				Domain:         usernameParts[2],
				UpdateEndpoint: updateEndpoint,
				ErrorEndpoint:  errorEndpoint,
			}
			if passwd.IsOauth {
				x.Oauth.AccessToken = passwd.Token
			} else {
				x.Password = passwd.Token
			}
			go checkCalendars(x, hash)
		}
	}
}

func main() {

	readConfig()

	// Check that redis is working.
	var err error
	if gRedis, err = redis.Dial("tcp", fmt.Sprintf("%s:%s", gServerConfig.RedisHostname, gServerConfig.RedisPort)); err != nil {
		log.Println(err == nil)
		log.Fatal("Error connecting to Redis. %s", err)
	}

	gCredentials = make(Credentials)

	go askClientsToRegisterAgain()
	go pollCalendars()

	http.HandleFunc("/register", registerHandler)

	var tls string
	if gServerConfig.UseTLS {
		tls = "(over TLS)"
	}
	log.Printf("Listening on %s:%s %s", gServerConfig.Hostname, gServerConfig.Port, tls)

	if gServerConfig.UseTLS {
		err = http.ListenAndServeTLS(gServerConfig.Hostname+":"+gServerConfig.Port,
			gServerConfig.CertFilename,
			gServerConfig.KeyFilename,
			nil)
	} else {
		for i := 0; i < 5; i++ {
			log.Println("This is a really unsafe way to run the push server.  Really.  Don't do this in production.")
		}
		err = http.ListenAndServe(gServerConfig.Hostname+":"+gServerConfig.Port, nil)
	}

	http.ListenAndServe("nikhilism.com:8009", nil)
}
