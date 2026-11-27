package legit

// material is every category. The texts live in the material_*.go files.
var material = []category{
	namesCategory,
	addressesCategory,
	reviewsCategory,
	supportCategory,
	pricesCategory,
	urlsCategory,
	codeCategory,
	otherLanguagesCategory,
}

// slotSets are the word lists of the material files; slots is all of them.
// A list name belongs to one file only, which the tests check.
var slotSets = []map[string][]string{
	sharedSlots, namesSlots, addressesSlots, reviewsSlots, supportSlots,
	pricesSlots, urlsSlots, codeSlots, otherLanguagesSlots,
}

var slots = func() map[string][]string {
	all := map[string][]string{}
	for _, set := range slotSets {
		for name, list := range set {
			all[name] = list
		}
	}
	return all
}()

// ep builds an endpoint from a method, a path and its fields as name and
// value in turn; the value txt marks the field that takes the text.
func ep(method, path string, nameValue ...string) endpoint {
	e := endpoint{method: method, path: path}
	for i := 0; i+1 < len(nameValue); i += 2 {
		e.fields = append(e.fields, [2]string{nameValue[i], nameValue[i+1]})
	}
	return e
}

// txt is the value of the field that takes the generated text.
const txt = payloadMark

// sharedSlots are lists that more than one category uses. Every person,
// mailbox and phone number is invented: the hosts are reserved names and the
// phone numbers lie in ranges set aside for fiction.
var sharedSlots = map[string][]string{
	"email": {
		"⟦email-user⟧@⟦email-host⟧",
	},
	"email-user": {
		"anna.kowalska", "j.okafor", "maria_g", "tom", "priya.sharma84", "chen.wei", "support", "billing",
		"o.brien", "lucas+orders", "s.dubois", "info", "hello", "yuki.tanaka", "dmitri.v", "fatima.haddad",
		"first.last", "accounts-payable", "no-reply", "k.papadopoulos", "ben+newsletter", "it-helpdesk",
	},
	"email-host": {
		"example.com", "example.org", "example.net", "mail.example.com", "corp.example.org", "school.example.net",
		"shop.test", "clinic.example", "studio.example.com", "uni.example.org",
	},
	"phone": {
		"(202) 555-0143", "+1 202 555 0178", "555-0199", "+44 20 7946 0958", "020 7946 0321", "+1-303-555-0122",
		"+61 491 570 156", "+44 7700 900123", "1-800-555-0100", "(415) 555-0167 ext. 12",
		"+1 (613) 555-0184",
	},
	"cur": {"$", "€", "£", "US$", "CA$", "A$"},
	"cents": {
		"00", "49", "50", "95", "99", "25", "90",
	},
	"weekday": {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"},
	"month": {
		"January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
		"November", "December",
	},
	"product": {
		"kettle", "office chair", "backpack", "phone case", "running shoes", "desk lamp", "coffee grinder",
		"standing desk", "wireless mouse", "mechanical keyboard", "yoga mat", "air fryer", "bike helmet",
		"water bottle", "noise-cancelling headphones", "espresso machine", "winter jacket", "tent", "blender",
		"monitor arm", "sofa cover", "bookshelf", "garden hose", "cordless drill", "baby monitor", "suitcase",
		"frying pan", "USB-C hub", "robot vacuum", "duvet", "smartwatch strap", "printer", "dog bed",
		"electric toothbrush", "sleeping bag", "router", "pressure cooker", "bedside table", "raincoat", "webcam",
	},
}
