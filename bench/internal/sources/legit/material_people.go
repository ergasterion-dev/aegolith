package legit

// Names of people and businesses as they are typed into name fields and
// customer searches. First and family names are combined freely, so every
// full name is invented.
var namesCategory = category{
	name: "names",
	templates: []string{
		"⟦first⟧ ⟦last⟧",
		"⟦first⟧ ⟦initial⟧. ⟦last⟧",
		"⟦last⟧, ⟦first⟧",
		"⟦last⟧, ⟦first⟧ ⟦initial⟧.",
		"⟦title⟧ ⟦first⟧ ⟦last⟧",
		"⟦title⟧ ⟦last⟧",
		"⟦first⟧ ⟦last⟧ ⟦name-suffix⟧",
		"⟦first⟧ ⟦last-plain⟧-⟦last-second⟧",
		"⟦first⟧ \"⟦nickname⟧\" ⟦last⟧",
		"⟦first⟧ '⟦nickname⟧' ⟦last⟧",
		"⟦first⟧ ⟦middle⟧ ⟦last⟧",
		"⟦initial⟧. ⟦initial⟧. ⟦last⟧",
		"⟦first⟧ & ⟦partner⟧ ⟦last⟧",
		"⟦first⟧ ⟦last⟧ (⟦name-role⟧)",
		"⟦first⟧ ⟦last⟧ c/o ⟦business⟧",
		"⟦business⟧",
		"⟦first⟧ ⟦last⟧, ⟦credential⟧",
		"The ⟦last⟧ Family",
		"⟦first⟧ ⟦last⟧ (née ⟦last-second⟧)",
		"⟦first⟧ and ⟦partner⟧ ⟦last-plain⟧-⟦last-second⟧",
	},
	endpoints: [3][]endpoint{
		{
			ep("GET", "/api/customers/search", "name", txt),
			ep("GET", "/directory", "q", txt, "page", "1"),
			ep("GET", "/api/v1/contacts", "filter", txt, "limit", "20"),
		},
		{
			ep("POST", "/api/profile", "display_name", txt),
			ep("PUT", "/api/account", "full_name", txt, "locale", "en-GB"),
			ep("POST", "/api/v1/contacts", "name", txt, "type", "person"),
		},
		{
			ep("POST", "/account/profile", "full_name", txt),
			ep("POST", "/signup", "name", txt, "newsletter", "on"),
			ep("POST", "/checkout/recipient", "recipient", txt, "gift", "no"),
		},
	},
}

var namesSlots = map[string][]string{
	"first": {
		"Anna", "James", "María", "José", "Zoë", "Renée", "Björn", "Søren", "Łukasz", "François", "Chloé",
		"Siobhán", "Íñigo", "Jürgen", "Åsa", "Priya", "Wei", "Yuki", "Dmitri", "Fatima", "Kwame", "Aoife",
		"Thabo", "Ngozi", "Mehmet", "Leila", "Mateus", "Ana Lúcia", "Jean-Pierre", "Mary-Kate", "Oluwaseun",
		"Sven", "Ingrid", "Tomás", "Nuala", "Rafael", "Hannah", "Oliver", "Amara", "Giulia", "Hiroshi", "Camille",
		"Stephen", "Deborah", "Luis", "Ayşe", "Paweł", "Katarzyna", "Elif", "Noah", "Sofía", "Abdullah", "Mei Ling",
		"D'Arcy", "Ta-Nehisi", "Eun-ji", "Günther", "Maëlle", "Bartholomew", "Li", "Jo", "Raúl", "Nađa", "Ciarán",
	},
	"middle": {
		"Marie", "Lee", "Ann", "José", "de Jesús", "Louise", "James", "Rose", "van", "Kofi", "Wei", "Grace",
		"Alexander", "Mae", "Jean", "Noor", "Elizabeth", "Xavier", "St. Clair", "del Carmen",
	},
	"partner": {
		"Maria", "Jerry", "Sam", "Alex", "Lena", "Pedro", "Chris", "Nora", "Ibrahim", "Sophie", "Tariq", "Linh",
		"Jakub", "Rosa", "Dev", "Isla",
	},
	"initial": {
		"A", "B", "C", "D", "E", "F", "G", "H", "J", "K", "L", "M", "N", "P", "R", "S", "T", "W",
	},
	"last": {
		"⟦last-plain⟧", "⟦last-marked⟧",
	},
	"last-plain": {
		"Smith", "Müller", "García", "Fernández", "Nguyen", "Kowalski", "Okafor", "Yamamoto", "Singh", "Patel",
		"Kim", "Haddad", "Papadopoulos", "Fitzgerald", "Novák", "Ångström", "Jensen", "Rossi", "Dubois", "Silva",
		"Öztürk", "Mbeki", "Tanaka", "Ivanova", "Hernández", "Schmidt", "Larsen", "Chowdhury", "Wójcik", "Petrović",
		"Moreau", "Nakamura", "Abara", "Lindqvist", "Castellanos", "Żuraw", "Ferreira", "Brown", "Dvořák", "Ó Briain",
		"Ahmed", "Baker", "Çelik", "Iglesias", "Jovanović", "Thompson", "Villanueva", "Zhang",
	},
	"last-marked": {
		"O'Brien", "O'Connor", "D'Angelo", "McDonald", "MacGregor", "van der Merwe", "de la Cruz", "Al-Sayed",
		"St. John", "Smith-Jones", "N'Diaye", "Ó Súilleabháin", "Le Blanc", "Dell'Acqua", "von Habsburg",
		"O’Neill", "Ben-David", "da Silva", "ter Horst", "Di Stefano", "El-Amin", "M'Baye", "bin Rashid",
		"Fitz-William", "De'Ath", "Mac an tSaoir",
	},
	"last-second": {
		"Jones", "López", "Meyer", "Clarke", "Andersen", "Ruiz", "Bianchi", "Taylor", "Mwangi", "Sato", "Evans",
		"Leclerc", "Hill", "Pérez", "Wood", "Roy",
	},
	"title": {
		"Dr.", "Mr.", "Mrs.", "Ms.", "Prof.", "Mx", "Dr", "Sr.", "Sra.", "Mme", "Herr", "Frau", "Rev.", "Capt.",
		"Prof. Dr.", "Dame", "Sir",
	},
	"name-suffix": {
		"Jr.", "Sr.", "III", "II", "PhD", "MD", "Esq.", "(she/her)", "(he/him)", "(they/them)", "OBE", "IV",
	},
	"credential": {
		"M.D.", "Ph.D.", "CPA", "RN, BSN", "P.Eng.", "MBA", "DDS", "LL.M.", "B.Sc. (Hons)", "FRCS",
	},
	"nickname": {
		"Bobby", "Ace", "Red", "Mac", "Sunny", "Doc", "Tex", "Kiki", "Lulu", "Big T", "The Hammer", "JJ", "Pip",
		"Mimi", "Coach", "Dee",
	},
	"name-role": {
		"billing contact", "account owner", "parent/guardian", "emergency contact", "site manager", "new owner",
		"on behalf of the tenant", "secretary", "authorised signatory", "work", "home", "maiden name on file",
	},
	"business": {
		"⟦last-plain⟧ & ⟦last-second⟧ ⟦business-form⟧",
		"⟦last-plain⟧ & Sons ⟦business-form⟧",
		"⟦last-plain⟧ & Daughters",
		"⟦last-marked⟧'s ⟦trade⟧",
		"⟦last-plain⟧'s ⟦trade⟧",
		"A+ ⟦trade⟧, Inc.",
		"⟦last-plain⟧ + ⟦last-second⟧ Architects",
		"⟦last-plain⟧, ⟦last-second⟧ & Co.",
		"The ⟦last-plain⟧ ⟦trade⟧ (est. ⟦#1890-2019⟧)",
		"⟦trade⟧ @ No. ⟦#2-99⟧",
		"⟦last-plain⟧ ⟦trade⟧ GmbH & Co. KG",
		"Café ⟦first⟧",
		"⟦first⟧'s ⟦trade⟧ #⟦#2-9⟧",
		"S.A.R.L. ⟦last-plain⟧ Frères",
		"⟦last-plain⟧/⟦last-second⟧ Studio",
		"\"⟦nickname⟧'s\" ⟦trade⟧",
	},
	"business-form": {"Ltd.", "LLC", "Inc.", "Pty Ltd", "GmbH", "S.L.", "B.V.", "Ltd", "& Co.", "LLP", "S.r.l.", "AB"},
	"trade": {
		"Bakery", "Plumbing", "Auto Repair", "Hair & Beauty", "Fish & Chips", "Books", "Bar & Grill", "Dry Cleaning",
		"Garden Centre", "Heating & Cooling", "Print Shop", "Pizzeria", "Bed & Breakfast", "Dental Care", "Cycles",
		"Flowers", "Tyres & Exhausts", "Pet Supplies", "Nails", "Accounting",
	},
}

// Postal addresses in the formats of several countries, and the second
// address lines and delivery notes that go with them. Streets, numbers and
// postcodes are combined freely; the towns are real.
var addressesCategory = category{
	name: "addresses",
	templates: []string{
		"⟦#1-9999⟧ ⟦street-us⟧ ⟦street-type-us⟧, ⟦city-us⟧ ⟦#10000-99999⟧",
		"⟦#1-9999⟧ ⟦street-us⟧ ⟦street-type-us⟧, ⟦unit-us⟧, ⟦city-us⟧ ⟦#10000-99999⟧",
		"⟦#1-999⟧ ⟦compass⟧ ⟦street-us⟧ ⟦street-type-us⟧ ⟦unit-us⟧\n⟦city-us⟧ ⟦#10000-99999⟧-⟦#1000-9999⟧\nUSA",
		"P.O. Box ⟦#10-9999⟧, ⟦city-us⟧ ⟦#10000-99999⟧",
		"⟦unit-uk⟧, ⟦#1-250⟧ ⟦street-uk⟧, ⟦city-uk⟧",
		"⟦#1-250⟧ ⟦street-uk⟧, ⟦city-uk⟧",
		"⟦house-name⟧, ⟦street-uk⟧, ⟦city-uk⟧, United Kingdom",
		"⟦street-de⟧ ⟦#1-180⟧, ⟦#10000-99999⟧ ⟦city-de⟧",
		"⟦street-de⟧ ⟦#1-180⟧⟦house-letter⟧, ⟦#10000-99999⟧ ⟦city-de⟧, Deutschland",
		"⟦street-de⟧ ⟦#1-180⟧/⟦#1-40⟧, ⟦#1010-9990⟧ ⟦city-at⟧, Österreich",
		"⟦street-de⟧ ⟦#1-180⟧, ⟦#1000-9658⟧ ⟦city-ch⟧, Schweiz",
		"⟦#1-140⟧ ⟦street-fr⟧, ⟦#10000-95999⟧ ⟦city-fr⟧",
		"⟦#1-140⟧ bis ⟦street-fr⟧, ⟦unit-fr⟧, ⟦#10000-95999⟧ ⟦city-fr⟧, France",
		"⟦street-es⟧, ⟦#1-200⟧, ⟦unit-es⟧, ⟦#10000-52999⟧ ⟦city-es⟧",
		"⟦street-it⟧ ⟦#1-200⟧, ⟦#10000-98999⟧ ⟦city-it⟧",
		"⟦street-nl⟧ ⟦#1-300⟧-⟦house-letter⟧, ⟦#1000-9999⟧ AB ⟦city-nl⟧",
		"⟦#1-400⟧ ⟦street-us⟧ ⟦street-type-us⟧, ⟦city-ca⟧",
		"⟦#1-99⟧/⟦#1-400⟧ ⟦street-us⟧ ⟦street-type-us⟧, ⟦city-au⟧ ⟦#2000-6999⟧",
		"⟦street-us⟧ ⟦street-type-us⟧ & ⟦street-us-b⟧ ⟦street-type-us⟧, ⟦city-us⟧",
		"⟦address-line-2⟧",
		"⟦address-line-2⟧ (⟦delivery-note⟧)",
		"⟦delivery-note⟧",
		"⟦#1-250⟧ ⟦street-uk⟧ - ⟦delivery-note⟧",
		"Attn: ⟦attn⟧, ⟦#1-9999⟧ ⟦street-us⟧ ⟦street-type-us⟧, ⟦unit-us⟧",
		"⟦city-us⟧ ⟦#10000-99999⟧ / ⟦street-us⟧ ⟦street-type-us⟧ ⟦#1-9999⟧",
		"⟦street-pl⟧ ⟦#1-150⟧/⟦#1-60⟧, ⟦#10-99⟧-⟦#100-999⟧ ⟦city-pl⟧",
		"⟦street-pt⟧, ⟦#1-900⟧ - ⟦unit-pt⟧, ⟦city-pt⟧",
	},
	endpoints: [3][]endpoint{
		{
			ep("GET", "/api/address/lookup", "q", txt),
			ep("GET", "/stores/nearby", "address", txt, "radius", "10"),
			ep("GET", "/api/v1/geocode", "address", txt, "format", "json"),
		},
		{
			ep("POST", "/api/addresses", "address", txt, "kind", "shipping"),
			ep("PUT", "/api/account/address", "line1", txt),
			ep("POST", "/api/v1/shipments/quote", "destination", txt, "service", "standard"),
		},
		{
			ep("POST", "/checkout/address", "address", txt, "save", "1"),
			ep("POST", "/account/addresses/new", "street_address", txt),
			ep("POST", "/delivery/instructions", "note", txt),
		},
	},
}

var addressesSlots = map[string][]string{
	"street-us": {
		"Main", "Oak", "Maple", "Martin Luther King Jr.", "Elm", "Washington", "Lakeview", "Sunset", "Park",
		"Cedar", "Hillcrest", "St. Mary's", "O'Farrell", "River", "Jefferson", "Magnolia", "Old Mill", "Peachtree",
		"Mission", "Juniper", "King's Cross", "El Camino Real", "Broad", "Chestnut", "Willow Creek", "Highland",
		"Coral Reef", "Prospect", "Stone Bridge", "Bay View",
	},
	"street-us-b": {
		"5th", "42nd", "Pine", "Market", "Union", "Lincoln", "Church", "Grand", "State", "Division",
	},
	"street-type-us": {"St", "Street", "Ave", "Ave.", "Blvd", "Rd", "Dr.", "Lane", "Way", "Ct", "Pkwy", "Pl.", "Terrace"},
	"compass":        {"N", "S", "E", "W", "N.", "NW", "SE", "North", "West"},
	"unit-us": {
		"Apt 4B", "Apt. #12", "Suite 300", "Ste. 210", "Unit 7", "#5", "Fl 2", "Bldg. C, Apt 14", "Rm 101",
		"Apt 3 (rear)", "PH-2", "Lot 18", "Unit B-204", "2nd floor, door on the left", "#1/2",
	},
	"city-us": {
		"Springfield, IL", "Portland, OR", "Austin, TX", "Columbus, OH", "Madison, WI", "Boise, ID", "Albany, NY",
		"Santa Fe, NM", "Raleigh, NC", "St. Louis, MO", "Coeur d'Alene, ID", "Winston-Salem, NC", "Tempe, AZ",
		"Burlington, VT", "Fort Collins, CO", "Honolulu, HI",
	},
	"city-ca": {
		"Toronto, ON M5V 2T6", "Montréal (Québec) H2X 1Y4", "Vancouver BC V6B 1A1", "Halifax, NS B3H 4R2",
		"Calgary, AB T2P 1J9", "Québec, QC G1R 4P5", "St. John's, NL A1C 5S7",
	},
	"city-au": {"Sydney NSW", "Melbourne VIC", "Brisbane QLD", "Perth WA", "Adelaide SA", "Hobart TAS"},
	"unit-uk": {
		"Flat 3", "Flat 12A", "Flat B", "Basement Flat", "Unit 4, The Old Brewery", "First Floor", "Top Floor Flat",
		"Room 214, Halls of Residence", "The Annexe", "Apartment 9, Block C", "Office 2.07",
	},
	"street-uk": {
		"High Street", "Church Lane", "Station Road", "Victoria Road", "King's Road", "St John's Wood Road",
		"The Green", "Mill Lane", "Queen's Gate", "Bishop's Walk", "Market Square", "Park Avenue", "London Road",
		"Abbey Close", "Shepherd's Bush Road", "The Crescent", "Chapel Street", "Castle Hill", "Rose & Crown Yard",
		"St. Andrew's Terrace",
	},
	"city-uk": {
		"Leeds LS1 4AB", "London SW1A 2AA", "Manchester M1 1AE", "Edinburgh EH1 1YZ", "Cardiff CF10 1EP",
		"Belfast BT1 5GS", "Bristol BS1 4DJ", "York YO1 7HH", "Bury St Edmunds IP33 1BT", "Stoke-on-Trent ST1 1LZ",
		"Newcastle upon Tyne NE1 7RU", "Weston-super-Mare BS23 1AT",
	},
	"house-name": {
		"Rose Cottage", "The Old Rectory", "Orchard House", "Dunroamin", "The Coach House", "Ty Gwyn", "Hillside",
		"\"Seaview\"", "The Willows", "Number One",
	},
	"house-letter": {"a", "b", "c", "A", "B", "D"},
	"street-de": {
		"Hauptstraße", "Bahnhofstr.", "Schillerstraße", "Goethestraße", "Am Mühlenbach", "Königsallee",
		"Friedrich-Ebert-Platz", "An der Alten Försterei", "Lindenweg", "Kurfürstendamm", "Max-Planck-Str.",
		"Unter den Eichen", "Große Bleichen", "Zum Weißen Roß", "Jahnstraße",
	},
	"city-de": {
		"Berlin", "München", "Köln", "Frankfurt am Main", "Düsseldorf", "Nürnberg", "Halle (Saale)",
		"Freiburg im Breisgau", "Mülheim an der Ruhr", "Lübeck", "Garmisch-Partenkirchen", "Weil am Rhein",
	},
	"city-at": {"Wien", "Graz", "Linz", "Salzburg", "Innsbruck", "St. Pölten", "Klagenfurt am Wörthersee"},
	"city-ch": {"Zürich", "Bern", "Basel", "Luzern", "St. Gallen", "Biel/Bienne", "Winterthur"},
	"street-fr": {
		"rue de la Paix", "avenue des Champs-Élysées", "boulevard Saint-Germain", "rue de l'Église", "place du Marché",
		"chemin des Vignes", "allée des Tilleuls", "rue Victor-Hugo", "quai de la Mégisserie", "impasse du Château",
		"rue du 8-Mai-1945", "avenue du Général-de-Gaulle", "rue d'Alsace", "cours Mirabeau",
	},
	"unit-fr": {
		"Bât. B", "Appt 12", "3e étage", "Résidence Les Lilas, esc. C", "porte gauche", "BP 40", "chez Mme Laurent",
	},
	"city-fr": {
		"Paris", "Lyon", "Marseille", "Aix-en-Provence", "Saint-Étienne", "L'Haÿ-les-Roses", "Besançon", "Nîmes",
		"Clermont-Ferrand", "Villeneuve-d'Ascq", "Orléans CEDEX 1", "Châlons-en-Champagne",
	},
	"street-es": {
		"Calle Mayor", "Avda. de la Constitución", "C/ San Juan", "Paseo de Gracia", "Plaza de España",
		"Carrer d'Aragó", "Calle del Río", "Camino Viejo de Leganés", "Rúa do Vilar", "Avda. de Andalucía",
		"Calle 13 de Septiembre", "Ronda de Sant Pere",
	},
	"unit-es": {"3º B", "2º izq.", "1º dcha.", "bajo A", "ático", "Esc. 2, 4º C", "piso 5, depto. 12", "local 3"},
	"city-es": {
		"Madrid", "Barcelona", "Sevilla", "Valencia", "A Coruña", "San Sebastián", "Málaga", "Santiago de Compostela",
		"Palma de Mallorca", "Alcalá de Henares", "L'Hospitalet de Llobregat", "Cádiz",
	},
	"street-it": {
		"Via Roma", "Corso Vittorio Emanuele II", "Piazza San Marco", "Via Dante Alighieri", "Viale dei Mille",
		"Via dell'Indipendenza", "Largo Garibaldi", "Vicolo del Forno", "Via XX Settembre", "Strada Nuova",
	},
	"city-it": {"Roma RM", "Milano MI", "Napoli NA", "Torino TO", "Firenze FI", "Bologna BO", "Reggio nell'Emilia RE", "L'Aquila AQ"},
	"street-nl": {
		"Keizersgracht", "Prinsengracht", "Dorpsstraat", "Stationsweg", "Van Goghlaan", "Burgemeester de Vlugtlaan",
		"'s-Gravendijkwal", "Oude Delft", "Kerkstraat",
	},
	"city-nl": {"Amsterdam", "Utrecht", "'s-Hertogenbosch", "Den Haag", "Groningen", "Capelle aan den IJssel", "Leiden", "Alphen aan den Rijn"},
	"street-pl": {
		"ul. Długa", "ul. Marszałkowska", "al. Jana Pawła II", "ul. Świętego Marcina", "os. Słoneczne", "pl. Wolności",
		"ul. Żeromskiego", "ul. 3 Maja",
	},
	"city-pl": {"Warszawa", "Kraków", "Łódź", "Wrocław", "Gdańsk", "Poznań", "Zielona Góra", "Bielsko-Biała"},
	"street-pt": {
		"Rua Augusta", "Av. Paulista", "Rua das Flores", "Travessa do Carmo", "Praça da Sé", "Rua 25 de Março",
		"Alameda Santos", "Largo do Chiado",
	},
	"unit-pt": {"3.º Esq.", "apto 42", "bloco B, sala 7", "2.º Dto.", "loja 5", "cj. 101", "r/c"},
	"city-pt": {
		"1100-053 Lisboa", "4000-322 Porto", "São Paulo - SP, 01310-100", "Rio de Janeiro - RJ, 20040-020",
		"3000-213 Coimbra", "Belo Horizonte/MG", "Florianópolis - SC",
	},
	"attn": {
		"Accounts Payable", "Front Desk", "Receiving Dept.", "HR / Payroll", "IT (2nd floor)", "Dr. Patel's office",
		"Returns", "Mail Room", "the caretaker", "Reception - ask for Sam", "Purchasing & Logistics",
	},
	"address-line-2": {
		"c/o ⟦attn⟧",
		"Apartment ⟦#1-90⟧, ⟦#4-12⟧th floor",
		"Building ⟦#1-20⟧, Gate ⟦house-letter⟧",
		"Entrance at the rear; buzzer #⟦#1-60⟧",
		"Flat above the ⟦address-shop⟧",
		"Next to the ⟦address-shop⟧, opposite the ⟦address-shop-b⟧",
		"Block ⟦house-letter⟧, Staircase ⟦#1-6⟧, Door ⟦#1-40⟧",
		"Industrial Estate, Unit ⟦#1-40⟧/⟦house-letter⟧",
		"Km ⟦#1-90⟧ on the old road, after the ⟦address-shop⟧",
		"Corner of ⟦street-us⟧ & ⟦street-us-b⟧",
		"Room ⟦#100-999⟧, ⟦address-building⟧",
		"⟦address-building⟧, Level ⟦#1-30⟧",
		"1st Floor (above the ⟦address-shop⟧)",
		"Suite #⟦#100-900⟧ - ⟦attn⟧",
		"House no. ⟦#1-200⟧-⟦house-letter⟧, Lane ⟦#1-12⟧, near the ⟦address-shop⟧",
	},
	"address-shop": {
		"pharmacy", "post office", "bakery", "petrol station", "primary school", "bus stop", "launderette",
		"corner shop", "church", "hardware store", "fish & chip shop", "community centre", "hairdresser's",
		"water tower", "old cinema", "vet's",
	},
	"address-shop-b": {
		"library", "park gate", "bank", "supermarket car park", "mosque", "fire station", "pub", "florist",
		"train station", "town hall",
	},
	"address-building": {
		"North Tower", "Science Block", "The Exchange", "Riverside House", "Building 7", "East Wing",
		"Student Union", "Terminal 2", "St. Luke's Hospital", "Harbour Centre", "City Hall Annex", "Tower B",
	},
	"delivery-note": {
		"Leave with the neighbour at no. ⟦#1-99⟧ if I'm out",
		"Please don't ring the bell - baby sleeping!",
		"Gate code is ⟦#1000-9999⟧#; leave the parcel behind the green bin",
		"Ring twice; the dog is loud but friendly :)",
		"Deliver to the side door (the front one sticks)",
		"Call ⟦phone⟧ on arrival, the intercom doesn't work",
		"If nobody answers, try the ⟦address-shop⟧ next door & ask for ⟦partner⟧",
		"Back porch is fine; do NOT leave it on the street side",
		"Weekdays 9-5 only, closed for lunch 12:30-1:30",
		"It's the house with the blue door, not the one the sat-nav says",
		"Please use the goods entrance; max. vehicle height 2.8 m",
		"Leave in the parcel box (code ⟦#100-999⟧*)",
		"Don't leave with the concierge, they're never there >:(",
		"3rd floor, no lift - sorry! Buzz \"⟦last-plain⟧\"",
		"Signature required; I work from home Tue/Thu",
		"Fragile: please hand it over, don't throw it over the fence",
		"Drop it at reception & have them stamp the delivery note",
		"After 6 pm please; before that there's no one in",
		"The entrance is on ⟦street-us⟧ ⟦street-type-us⟧, not on the main road",
		"Put it in the shed (unlocked) and close the gate behind you",
		"Farm at the end of the track; follow the signs for \"⟦house-name-plain⟧\"",
		"Hand to security at Gate ⟦#1-9⟧; they'll sign for it",
	},
	"house-name-plain": {"Rose Cottage", "Orchard House", "Hillside", "The Willows", "Brook Farm", "Seaview", "Four Winds"},
}
