package strength

import "strings"

// commonPasswords is a short list of the passwords and password stems
// that top every breach corpus (English and French). Matching is
// case-insensitive, accent-folded and leetspeak-aware, both for the whole
// candidate and for any substring of it.
const commonPasswords = `
123456 1234567 12345678 123456789 1234567890 12345678910 111111 000000 123123
654321 666666 121212 112233 123321 159753 147258 789456 987654321 696969
password passw0rd password1 password12 password123 motdepasse mdp
qwerty qwerty123 azerty azerty123 azertyuiop qwertyuiop qwertz 1q2w3e 1q2w3e4r
1qaz2wsx zaq12wsx 1qazxsw2 abc123 abcd1234 aaaaaa iloveyou jetaime
letmein welcome welcome1 bienvenue changeme changeit default secret
admin admin123 administrator administrateur root toor master superuser
dragon monkey shadow sunshine princess football baseball soccer hockey
starwars pokemon superman batman trustno1 whatever freedom killer
michael jordan jennifer hunter ranger buster thomas charlie andrew
soleil chouchou doudou loulou nicolas julien camille marseille
1234qwer qwer1234 asdf1234 zxcvbnm asdfghjkl test test123 testtest
guest login access access14 hello hello123 love lovely flower
`

// dictionaryWords are frequent English and French words, plus the
// vocabulary an operator is tempted to use for an admin console. Each
// costs an attacker about as much as a word ranked a few thousand in a
// real cracking dictionary.
//
//nolint:misspell // French words (decembre, ...) are intentional
const dictionaryWords = `
pass password passe passphrase motdepasse mot word secret secrets secure
security securite securise safe safety private prive key keys cle clef
admin administrator administrateur root user users utilisateur login logon
account compte access acces welcome bienvenue hello bonjour salut coucou
master super power strong robust robuste solide fort forte tres very
system systeme server serveur service cloud network reseau domain domaine
company entreprise societe office bureau team equipe project projet
console portal portail manager gestion vault coffre token jeton
seal sceau cachet keeper gardien guard garde lock locked cadenas
change changeme update default temp temporary test testing demo
spring summer autumn winter printemps ete automne hiver
january february march april june july august september october
november december janvier fevrier mars avril juin juillet aout
septembre octobre novembre decembre monday tuesday wednesday thursday
friday saturday sunday lundi mardi mercredi jeudi vendredi samedi
dimanche today tomorrow yesterday morning evening night nuit jour
love amour heart coeur happy heureux family famille friend friends ami
amie amis maison house home world monde life vie dream reve
blue bleu red rouge green vert black noir white blanc yellow jaune
orange purple violet pink rose gold silver argent
dragon tiger tigre lion eagle aigle wolf loup bear ours horse cheval
cat chat dog chien chien monkey bird oiseau fish poisson
football soccer tennis rugby hockey basket baseball golf
paris france lyon marseille london londres europe america
apple pomme banana banane cherry cerise chocolate chocolat coffee cafe
music musique guitar guitare piano movie film
star stars etoile sun soleil moon lune sky ciel sea mer ocean
fire feu water eau earth terre wind vent ice glace snow neige storm
king roi queen reine prince princess princesse knight chevalier
magic magie angel ange devil diable ghost shadow ombre
freedom liberte victory victoire hunter killer ninja pirate
computer ordinateur internet google microsoft windows linux apple
mail email courriel message letter lettre
alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo
lima mike november oscar papa quebec romeo sierra tango uniform victor
whiskey xray yankee zulu
one two three four five six seven eight nine ten
un deux trois quatre cinq sept huit neuf dix
zero first premier last dernier new nouveau nouvelle old vieux
big grand petit small little
`

var (
	commonSet = wordSet(commonPasswords)
	dictSet   = wordSet(dictionaryWords)
)

func wordSet(list string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.Fields(list) {
		out[w] = true
	}
	return out
}
