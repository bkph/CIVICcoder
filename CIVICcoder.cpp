/////////////////////////////////////////////////////////////////////////////////////////////

// CIVICcoder.cpp

// (*) Encode (and decode) CIVIC (civic location information) strings which contain:
//	    (i) CIVIC_LOCATION subelement, (ii) MAP_URL subelement. See IETF RFC 4776.
//		The CIVIC string is used in hostapd.conf to provide civic location information for the FTM RTT responder,
//		see 9.4.2.22.13
//		It's contents could be provided by RangingResult.getLcr() in Android - but that is blacklisted!,
//		It provides input data for	Android RangingResult.toCivicLocationSparseArray() parser.

//		CA_Type codes used in civic string are defined in IETF RFC 4776 https://tools.ietf.org/html/rfc4776 
//		IETF RFC 6225: https://tools.ietf.org/html/rfc6225 

//	Based on the IEEE P802.11-REVmc/D8.0 spec section 9.4.2.22, under Measurement Report Element.
//	IEEE 8011-2016, RFC 6225, RFC 4776, and IETF RFC 3986 (with help from Roy Want).

#define  COPYRIGHT  \
	"Copyright (c) 2019 Berthold K.P. Horn <http://people.csail.mit.edu/bkph>." \
	"This source code is distributed under terms of the GNU General Public License," \
	"Version 3,  which grants certain rights to copy, modify, and redistribute." \
	"The license can be found at <http://www.gnu.org/licenses/>." \
	"There is no express or implied warranty, including merchantability or fitness" \
	"for a particular purpose." 

#define  VERSION   "Version 0.8"

////////////////////////////////////////////////////////////////////////////////////////////////

// TODO: currently location civic subelement does not work on Android end of the pipe...

// TODO: provide for some form of UTF8 string coding (for CA Types in civic string) ?

////////////////////////////////////////////////////////////////////////////////////////////////

// C/C++ code for MicroSoft Visual C++ 2017

// #include "pch.h"	// for MicroSoft Visual Studio 2017

#define _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES 1 
#define _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES_COUNT 1

// #define _CRT_SECURE_NO_WARNINGS 

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#define INLINE __inline

//////////////////////////////////////////////////////////////////////////////////////////////

#define MEASURE_TOKEN 1

#define MEASURE_REQUEST_MODE 0

// Type of Measurement Report
// NOTE: code below deals with Measurement Types LOCATION_CIVIC_TYPE (11)

enum measurement_type {
//	BEACON_TYPE = 5,
//	FRAME_TYPE = 6,
	LCI_TYPE = 8,				// MEASURE_TYPE_LCI
	LOCATION_CIVIC_TYPE = 11,	// MEASURE_TYPE_LOCATION_CIVIC
//	LOCATION_IDENTIFIER_TYPE = 12,
//	FINE_TIME_MEASUREMENT_RANGE_TYPE = 16
};

// Subelement IDs for Location Civic report
// NOTE: code below deals with LOCATION_CIVIC (ID 0) and with MAP_IMAGE_CIVIC (ID 5), 
// (because that is what Android API makes provision for currently)
// TODO: deal with LOCATION_SHAPE_CIVIC (ID 4) ? when Android supports it ?
// TODO: deal with COLOCATED_BSSID (ID 7) ? assuming it does exist in CIVIC element (*) ?

enum civic_subelement_code {
	LOCATION_CIVIC = 0,
//	ORIGINATOR_MAC_ADDRESS = 1,
//	TARGET_MAC_ADDRESS = 2,
	LOCATION_REFERENCE_CIVIC = 3,
	LOCATION_SHAPE_CIVIC = 4,
	MAP_IMAGE_CIVIC = 5,
//	RESERVED = 6,	
//	COLOCATED_BSSID = 7,	// ?
//	VENDOR_SPECIFIC = 221
};

// Note: When the Civic Location Type field is IETF RFC 4776, the Optional Subelements field optionally
// includes the Location Reference, Location Shape, Map Image, and Vendor Specific subelements.
// (*) This list does not include Colocated BSSID.

//	Note: Subelements are formatted exactly like elements 

//////////////////////////////////////////////////////////////////////////////////////////////

const char *copyright=COPYRIGHT;

const char *version=VERSION;

// Global flags controlling verbosity - set from command line

int verboseflag = 1;	// -v
int traceflag = 0;		// -t
int debugflag = 0;		// -d

int checkflag = 0;		// -c (check result after decoding or encoding)

int sampleflag = 0;		// run an example of decoding and encoding an CIVIC string

///////////////////////////////////////////////////////////////////////////////

char const * civicstring = NULL;	//  civic string to decode if given on command line using -civic=...

char const * mapimagestring = NULL;	// map URL given on command line using -mapimage=https://... IETF RFC 3986

int mapmemetype = 0;				// map meme --- default URL_DEFINED or given on command line using -mapmeme=...

char const ** CA = NULL;			// array of strings for civic location address values given on command line

char const *country_code="US";		// (default) civic location country - given on command line using -country=...

/////////////////////////////////////////////////////////////////////////////////////////////

// Utility functions

const char INLINE *strndup(const char *str, int nlen) {
	char *strnew = (char *) malloc(nlen+1);
//	strncpy(strnew, str, nlen);	// generic C version
	strncpy_s(strnew, nlen+1, str, nlen);	// "safe" 
	strnew[nlen]='\0';	// null terminate
	return strnew;
}

int INLINE hextoint(int c) {	// hex character to integer
	if (c >= '0' && c <= '9') return (c & 0x0F);
	else if (c >= 'A' && c <= 'F') return (c & 0x0F) + 9;
	else if (c >= 'a' && c <= 'f') return (c & 0x0F) + 9;
	printf("ERROR in conversion from hexadecimal char to int: char %d\n", c);
	return 0;
}

int INLINE inttohex(int k) {	// integer to hex character (lc)
	if (k >= 0 && k <= 15) return "0123456789abcdef"[k]; 
	printf("ERROR in conversion from int to hexadecimal char: int %d\n", k);
	return 0;
}

int INLINE getoctet(const char *str, int nbyt) { // big-endian
	return (hextoint(str[nbyt*2]) << 4) | hextoint(str[nbyt*2 + 1]);
}

char *gethexstring(const char *str, int nbyt, int nlen) {
	char *text = (char *) malloc(nlen+1);
	for (int k = 0; k < nlen; k++)
		text[k] =  (char) getoctet(str, nbyt++);
	text[nlen] = '\0';	// null terminate (assumes space available)
	return text;
}

int INLINE putoctet(char *str, int nbyt, int oct) {	// big-endian
	str[nbyt*2] = (char)inttohex(oct >> 4);
	str[nbyt*2 + 1] = (char)inttohex(oct & 0x0F);
	return nbyt + 1;
}

int puthexstring(char *str, int nbyt, int nlen, const char *line) {
	for (int k = 0; k < nlen; k++)
		nbyt = putoctet(str, nbyt, line[k]);
	return nbyt;
}

////////////////////////////////////////////////////////////////////////////////////////////

// TODO: use the following to support UTF8 in strings (particularly for CA values)
// sscanf(str, "=U+%x", &code); ?

#define BYTE unsigned char

BYTE *utf8_from_unicode(int num) {	// UTF8 <= Unicode
	int nlen;
	if (! (num & ~0x7F)) nlen = 1;			// num <128
	else if (! (num & ~0x7FF)) nlen = 2;	// num < 2048
	else if (! (num & ~0xFFFF)) nlen = 3;	// num < 65536
	else if (! (num & ~0x1FFFFF)) nlen = 4;	// num < 2097152
	else {
		printf("ERROR: out of range %d > %d\n", num, 0x1FFFFF);	// 2097151
		return NULL;
	}
	BYTE *str = (BYTE *) malloc((nlen+1) * sizeof(BYTE));
	if (! (num & ~0x7F)) {		// num < 0x80
		str[0] = (BYTE) num;
	}
	else if (! (num & ~0x7FF)) {	// num < 0x800
		str[0] = (BYTE) ((num >> 6) | 0xC0);	// 192
		str[1] = (BYTE) ((num & 0x3F) | 0x80);	// 128
	}
	else if (! (num & ~0xFFFF)) {	// num < 0x10000
		str[0] = (BYTE)  ((num >> 12) | 0xE0);			// 224
		str[1] = (BYTE) (((num >>  6) & 0x3F) | 0x80);	// 128
		str[2] = (BYTE)  ((num & 0x3F) | 0x80);			// 128
	}
	else if (! (num & ~0x1FFFFF)) {	// num < 0x200000
		str[0] = (BYTE)  ((num >> 18) | 0xF0);			// 240
		str[1] = (BYTE) (((num >> 12) & 0x3F) | 0x80);	// 128
		str[2] = (BYTE) (((num >>  6) & 0x3F) | 0x80);	// 128
		str[3] = (BYTE)  ((num & 0x3F) | 0x80);			// 128
	}
	str[nlen] = '\0';	// zero terminate
	return str;
}

int unicode_from_utf8(const BYTE *str) {	// UNICODE <= UTF8 
	int ord0 = str[0];
	if ((ord0 & 0x80) == 0x00)return ord0;
	int ord1 = str[1];
	if ((ord0 & 0xE0) == 0xC0)
		return (ord0 & ~0xC0) << 6 | (ord1 & ~0x80);
	int ord2 = str[2];
	if ((ord0 & 0xF0) == 0xE0)
		return (ord0 & ~0xE0) << 12 | (ord1 & ~0x80) << 6 | (ord2 & ~0x80);
	int ord3 = str[3];
	if ((ord0 & 0xF8) == 0xF0)
		return (ord0 & ~0xF0) << 18 | (ord1 & ~0x80) << 12 | (ord2 & ~0x80) << 6 | (ord3 & ~0x80);
	printf("ERROR: out of range 0x%2x 0x%2x 0x%2x 0x%2x %s\n", ord0, ord1, ord2, ord3, str);
	return -1;
}

void test_utf_unicode (int umax) {
	for (int k=0; k < umax; k++) {
		BYTE *str = utf8_from_unicode(k);
		int n = unicode_from_utf8(str);
		if (n != k) {
			printf("ERROR: k %d n %d %s\n", k, n, str);
			fflush(stdout);
		}
		else if (traceflag) printf("k %d\tn %d\t%s\t%d\n", k, n, str, strlen((char *)str));
		free(str);
	}
}

////////////////////////////////////////////////////////////////////////////////////////

// CA_Type codes used in civic string - RFC 4776 https://tools.ietf.org/html/rfc4776 
// Default names for CA Type keys here taken from Android CivicLocationKeys class

#define MAX_CA_TYPE 255

// Note: two (upper case) character country_code given separately (i.e. not a CA Type)
// Note: the following provides for some alternate names for types...

enum CA_types {
	LANGUAGE=0,				// i-default ISO
	STATE=1,				// A1 national subdivision (state, canton, region, province, prefecture)
	COUNTY=2,				// A2 county, parish, gun (JP), district (IN)
	CITY=3, TOWN=3,			// A3 city, township, shi (JP)
	BOROUGH=4,				// A4 city division, burough, city district, ward, chou (JP)
	NEIGHBORHOOD=5, BLOCK=5, // A5 neighborhood, block
	GROUP_OF_STREETS=6,		// A6 group of streets below neighborhood level (NOT: street)
	PRD=16, LEADING_STREET_DIRECTION=16, // e.g. N
	POD=17, TRAILING_STREET_SUFFIX=17,	// e.g. SW
	STS=18, STREET_SUFFIX=18,			// suffix or type e.g. Ave
	HNO=19, HOUSE_NUMBER=19, NUMBER=19, // e.g. 123
	HNS=20, HOUSE_NUMBER_SUFFIX=20,		// e.g. A
	LMK=21, LANDMARK=21, VANITY=21,		// landmark or vanity address e.g. Columbia University
	LOC=22, ADDITIONAL_LOCATION=22,		// e.g. South Wing
	NAM=23, NAME_OCCUPANT=23, NAME=23,	// e.g. Joe's Barbershop
	POSTAL_CODE=24, ZIP_CODE=24, ZIP=24, 
	BUILDING=25, BLDG=25,				// e.g. Hammond library
	APT=26, APARTMENT=26, UNIT=26, SUITE=26, // unit (apartment, suite)
	FLOOR=27, FLR=27, 
	ROOM=28, ROOM_NUMBER=28,
	TYPE_OF_PLACE=29, PLACE_TYPE=29,	// e.g. office
	PCN=30, POSTAL_COMMUNITY_NAME=30, 
	PO_BOX=31, POB=31,
	ADDITIONAL_CODE=32,
	DESK=33, SEAT=33, CUBICLE=33,	// seat (desk, cubicle, workstation)
	PRIMARY_ROAD_NAME=34, ROAD=34, STREET=34,	// e.g. Broadway (does *not* include number)
	ROAD_SECTION=35,				// e.g. 12
	BRANCH_ROAD_NAME=36,			// e.g. Lane 7
	SUBBRANCH_ROAD_NAME=37,			// e.g. Alley 8
	STREET_NAME_PRE_MODIFIER=38,	// e.g. Old
	STREET_NAME_POST_MODIFIER=39,	// e.g. Service
	SCRIPT=128,						// default is Latn
	RESERVED=255
};

// Decoded CA type code key strings based on Android CivicLocationKeys class

char *CA_type_string(int k) {
	switch (k) {
		case LANGUAGE: return "LANGUAGE";
		case STATE: return "STATE";
		case COUNTY: return "COUNTY";
		case CITY: return "CITY";
		case BOROUGH: return "BOROUGH";
		case NEIGHBORHOOD: return "NEIGHBORHOOD";
		case GROUP_OF_STREETS: return "GROUP_OF_STREETS";
		case PRD: return "PRD";	// "LEADING_STREET_DIRECTION"
		case POD: return "POD";	// "TRAILING_STREET_SUFFIX"
		case STS: return "STS";	// "STREET_SUFFIX"
		case HNO: return "HNO";	// "NUMBER", "HOUSE_NUMBER"
		case HNS: return "HNS";	// "HOUSE_NUMBER_SUFFIX"
		case LMK: return "LMK";	// "LANDMARK"
		case LOC: return "LOC";	// "ADDITIONAL_LOCATION"
		case NAM: return "NAM";	// "NAME", "NAME_OCCUPANT"
		case POSTAL_CODE: return "POSTAL_CODE";	// "ZIP_CODE"
		case BUILDING: return "BUILDING";
		case APT: return "APT";
		case FLOOR: return "FLOOR";	// FLR
		case ROOM: return "ROOM";
		case TYPE_OF_PLACE: return "TYPE_OF_PLACE";
		case PCN: return "PCN";	// "POSTAL_COMMUNITY_NAME"
		case PO_BOX: return "PO_BOX";
		case ADDITIONAL_CODE: return "ADDITIONAL_CODE";
		case DESK: return "DESK";	// "SEAT"
		case PRIMARY_ROAD_NAME: return "PRIMARY_ROAD_NAME";	// "ROAD", "STREET"
		case ROAD_SECTION: return "ROAD_SECTION";
		case BRANCH_ROAD_NAME: return "BRANCH_ROAD_NAME";
		case SUBBRANCH_ROAD_NAME: return "SUBBRANCH_ROAD_NAME";
		case STREET_NAME_PRE_MODIFIER: return "STREET_NAME_PRE_MODIFIER";
		case STREET_NAME_POST_MODIFIER: return "STREET_NAME_POST_MODIFIER";
		case SCRIPT: return "SCRIPT";
		case RESERVED: return "RESERVED";
		default: return "Unknown CA type";
	}
}

// Following allows for several variants (and also direct numeric specification)

int encode_CA_type_string(const char *str, int nlen) {
	int code;
	if (debugflag) printf("str %s nlen %d (%s)\n", str, nlen, str+nlen+1);
//	if (sscanf(str, "%d=", &code) == 1) return code;	// allow for numeric specification
	if (sscanf_s(str, "%d=", &code) == 1) return code;	// "safe" version
	switch(nlen) {
		case 3:
			if (_strnicmp(str, "PRD", nlen) == 0) return PRD;	 
			else if (_strnicmp(str, "POD", nlen) == 0) return POD;	
			else if (_strnicmp(str, "STS", nlen) == 0) return STS;	
			else if (_strnicmp(str, "HNS", nlen) == 0) return HNS;	
			else if (_strnicmp(str, "LOC", nlen) == 0) return LOC; 
			else if (_strnicmp(str, "NAM", nlen) == 0) return NAM;	
			else if (_strnicmp(str, "APT", nlen) == 0) return APT;
			else if (_strnicmp(str, "PCN", nlen) == 0) return PCN;	
			else if (_strnicmp(str, "HNO", nlen) == 0) return HNO;	// alias
			else if (_strnicmp(str, "LMK", nlen) == 0) return LMK;	// alias
			else if (_strnicmp(str, "ZIP", nlen) == 0) return ZIP;	// alias
			else if (_strnicmp(str, "POB", nlen) == 0) return POB;	// alias
			else if (_strnicmp(str, "FLR", nlen) == 0) return FLR;	// alias
			break;
		case 4:
			if (_strnicmp(str, "CITY", nlen) == 0) return CITY;
			else if (_strnicmp(str, "ROOM", nlen) == 0) return ROOM;
			else if (_strnicmp(str, "SEAT", nlen) == 0) return SEAT;
			else if (_strnicmp(str, "TOWN", nlen) == 0) return TOWN;	// alias
			else if (_strnicmp(str, "NAME", nlen) == 0) return NAME;	// alias
			else if (_strnicmp(str, "DESK", nlen) == 0) return DESK;	// alias
			else if (_strnicmp(str, "ROAD", nlen) == 0) return ROAD;	// alias
			else if (_strnicmp(str, "BLDG", nlen) == 0) return BLDG;	// alias
			else if (_strnicmp(str, "UNIT", nlen) == 0) return UNIT;	// alias
			break;
		case 5:
			if (_strnicmp(str, "STATE", nlen) == 0) return STATE;
			else if (_strnicmp(str, "BLOCK", nlen) == 0) return BLOCK;
			else if (_strnicmp(str, "FLOOR", nlen) == 0) return FLOOR;
			else if (_strnicmp(str, "SUITE", nlen) == 0) return SUITE;
			break;
		case 6:
			if (_strnicmp(str, "COUNTY", nlen) == 0) return COUNTY;
			else if (_strnicmp(str, "NUMBER", nlen) == 0) return NUMBER;
			else if (_strnicmp(str, "PO_BOX", nlen) == 0) return PO_BOX;
			else if (_strnicmp(str, "SCRIPT", nlen) == 0) return SCRIPT;
			else if (_strnicmp(str, "STREET", nlen) == 0) return STREET;	// alias
			break;
		case 7:
			if (_strnicmp(str, "BOROUGH", nlen) == 0) return BOROUGH;
			else if (_strnicmp(str, "CUBICLE", nlen) == 0) return CUBICLE;
			break;
		case 8:
			if (_strnicmp(str, "LANGUAGE", nlen) == 0) return LANGUAGE;
			else if (_strnicmp(str, "LANDMARK", nlen) == 0) return LANDMARK;
			else if (_strnicmp(str, "BUILDING", nlen) == 0) return BUILDING;
			else if (_strnicmp(str, "ZIP_CODE", nlen) == 0) return ZIP_CODE;	// alias
			break;
		case 9:
			if (_strnicmp(str, "RESERVED", nlen) == 0) return RESERVED	;
			else if (_strnicmp(str, "APARTMENT", nlen) == 0) return APARTMENT;	// alias
			break;
		case 10:
			if (_strnicmp(str, "PLACE_TYPE", nlen) == 0) return PLACE_TYPE;		// alias
			break;			
		case 11:
			if (_strnicmp(str, "POSTAL_CODE", nlen) == 0) return POSTAL_CODE;	
			else if (_strnicmp(str, "ROOM_NUMBER", nlen) == 0) return ROOM_NUMBER;	// alias
			break;
		case 12:
			if (_strnicmp(str, "NEIGHBORHOOD", nlen) == 0) return NEIGHBORHOOD;
			else if (_strnicmp(str, "HOUSE_NUMBER", nlen) == 0) return HOUSE_NUMBER;	// alias
			else if (_strnicmp(str, "ROAD_SECTION", nlen) == 0) return ROAD_SECTION;	// alias
			break;
		case 13:
			if (_strnicmp(str, "NAME_OCCUPANT", nlen) == 0) return NAME_OCCUPANT;		// alias
			else if (_strnicmp(str, "TYPE_OF_PLACE", nlen) == 0) return TYPE_OF_PLACE;	// alias
			else if (_strnicmp(str, "STREET_SUFFIX", nlen) == 0) return STREET_SUFFIX;	// alias
			break;
		case 15:
			if (_strnicmp(str, "ADDITIONAL_CODE", nlen) == 0) return ADDITIONAL_CODE;	// alias
			break;
		case 16:
			if (_strnicmp(str, "GROUP_OF_STREETS", nlen) == 0) return GROUP_OF_STREETS;		// alias
			else if (_strnicmp(str, "BRANCH_ROAD_NAME", nlen) == 0) return BRANCH_ROAD_NAME;	// alias
			break;
		case 17:
			if (_strnicmp(str, "PRIMARY_ROAD_NAME", nlen) == 0) return PRIMARY_ROAD_NAME;
			break;
		case 19:
			if (_strnicmp(str, "HOUSE_NUMBER_SUFFIX", nlen) == 0) return HOUSE_NUMBER_SUFFIX;	
			else if (_strnicmp(str, "ADDITIONAL_LOCATION", nlen) == 0) return ADDITIONAL_LOCATION; // alias
			else if (_strnicmp(str, "SUBBRANCH_ROAD_NAME", nlen) == 0) return SUBBRANCH_ROAD_NAME; // alias
			break;
		case 21:
			if (_strnicmp(str, "POSTAL_COMMUNITY_NAME", nlen) == 0) return POSTAL_COMMUNITY_NAME;	
			break;
		case 22:
			if (_strnicmp(str, "TRAILING_STREET_SUFFIX", nlen) == 0) return TRAILING_STREET_SUFFIX;
			break;
		case 24:
			if (_strnicmp(str, "LEADING_STREET_DIRECTION", nlen) == 0) return LEADING_STREET_DIRECTION;	// alias
			break;
		default: break;
	}
	 return -1;	// did not find match
}

//////////////////////////////////////////////////////////////////////////////////

#define MAX_MEME_CODE 17

enum map_image_types { // IETF RFC 3986
	// default: URL_DEFINED=0 -> file extension defines mime type (i.e. self-descriptive)
	URL_DEFINED=0,	PNG=1,	GIF=2,	JPEG=3,	SVG=4,	DXF=5,	DWG=6,	DWF=7,	CAD=8,	TIFF=9,
	GML=10,	KML=11,	BMP=12,	PGM=13,	PPM=14,	XBM=15,	XPM=16,	ICO=17
//	18–255 Reserved
};

const char *map_type_string[] = { 
	"URL Defined", "Png", "Gif", "Jpeg", "Svg", "dxf", "Dwg", "Dwf", "cad", "Tiff",
	"gml", "Kml", "Bmp", "Pgm", "ppm", "Xbm", "Xpm", "ico"
};

int encode_map_meme_type (const char *str) {
	int code;
//	if (sscanf(str, "%d", &code) == 1) return code;	// allow for numeric specification
	if (sscanf_s(str, "%d", &code) == 1) return code;	// "safe" version
	for (int k = 0; k <= MAX_MEME_CODE; k++)
		if (_stricmp(str, map_type_string[k]) == 0) return k;
	if (_stricmp(str, "jpg")) return JPEG;	// alternate spelling
	if (_stricmp(str, "tif")) return TIFF;	// alternate spelling
	if (_stricmp(str, "url")) return URL_DEFINED;
	printf("ERROR: don't understand map meme %s\n", str);
	return URL_DEFINED; // use default if can't understand string
}

const char *map_meme_type_string (int k) {
	if (k >= 0 && k <= MAX_MEME_CODE) return map_type_string[k];
	else return "ERROR: meme type unknown";
}

//////////////////////////////////////////////////////////////////////////////////

void checksettings (void) {
	if (strlen(country_code) != 2) {
		printf("ERROR: country code %s should be two letters, not %d\n", country_code,strlen(country_code));
		country_code = strndup(country_code, 2);	// shorten it...
	}
}

/////////////////////////////////////////////////////////////////////////////////////////

// Buggy examples originally from hostapd.conf

// const char *civic =  "01000b0000f9555302f50102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5";

const char *civic1 = "01000b00f9555302f50102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5";

// buggy example from https://w1.fi/cgit/hostap/plain/tests/hwsim/test_gas.py

const char *civic1a = "01000b0000f9555302f50102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5";

// another buggy example, from https://w1.fi/cgit/hostap/plain/tests/hwsim/test_rrm.py

const char *civic2="01000b0011223344556677889900998877665544332211aabbccddeeff";

///////////////////////////////////////////////////////////////////////////////

void showusage(void) {
	printf("-v\t\tFlip verbose mode %s\n", verboseflag ? "off":"on");
	printf("-t\t\tFlip trace mode %s\n", traceflag ? "off":"on");
	printf("-d\t\tFlip debug mode %s\n", debugflag ? "off":"on");
	printf("-c\t\tFlip checking mode %s\n", checkflag ? "off":"on");
	printf("\n");
	printf("-civic=...\tDecode given CIVIC string\n");
	printf("\n");
	printf("To encode a CIVIC string use the CA keys and strings, for example:\n");
	printf("\n");
	printf("-country=US -state=Massachussets -city=Cambridge -street=Vassar -number=32...\n");
	printf("\n");
	printf("-map=<URI>\t(including file extension)\n");
	printf("-meme=...\tmeme type (if not obvious from file extension)\n");
	printf("\n");
	printf("-sample\t\tShow example decoding / encoding\n");
	printf("-?\t\tPrint this command line argument summary\n");
	printf("-version=...\t%s\n", version);
	fflush(stdout);
	exit(1);
}

// Allow for quoted string in command line arguments - strip quotation marks 

const char *grabstring (const char *arg) {	
	const char *streq=strchr(arg, '=');	// find value string
	if (streq == NULL) {
		printf("ERROR: missing '=' in %s\n", arg);
		return NULL;	// can't happen
	}
	int nlen = strlen(streq+1);
	// only provide for matching opening and closing quotes
	if ((*(streq+1) == '"') && (*(streq+nlen) == '"'))
		return strndup(streq+2, nlen-2);
//	else return streq+1;
	else return strndup(streq+1, nlen);
}

int commandline(int argc, const char *argv[]) {
	int firstarg = 1;
	while (firstarg < argc && *argv[firstarg] == '-') {
		const char *arg = argv[firstarg];
		if (strcmp(arg, "-v") == 0) verboseflag = !verboseflag;
		else if (strcmp(arg, "-t") == 0) traceflag = !traceflag;
		else if (strcmp(arg, "-d") == 0) debugflag = !debugflag;
		else if (strcmp(arg, "-c") == 0) checkflag = !checkflag;
		else if (strcmp(arg, "-sample") == 0) sampleflag = !sampleflag;
		else if (_strnicmp(arg, "-civic=", 7) == 0) 	// string to decode (uc or lc)
			civicstring = grabstring(arg);
//		paramater for construction of civic element
		else if (_strnicmp(arg, "-map=", 5) == 0)		// MAP URL with extension
			mapimagestring = grabstring(arg);
		else if (_strnicmp(arg, "-mapimage=", 10) == 0)  // MAP URL with extension
			mapimagestring = grabstring(arg);
		else if (_strnicmp(arg, "-meme=", 6) == 0)		// map meme type
			mapmemetype = encode_map_meme_type(arg+6);
		else if (_strnicmp(arg, "-mapmeme=", 9) == 0)	// map meme type
			mapmemetype = encode_map_meme_type(arg+9);
		else if (_strnicmp(arg, "-country=", 9) == 0)
			country_code = grabstring(arg);
		else if (_strnicmp(arg, "-country_code=", 14) == 0)
			country_code = grabstring(arg);
		else if (strcmp(arg, "-?") == 0) showusage();
		else if (strcmp(arg, "-help") == 0) showusage();
		else { //	try keys for civic string
			const char *argequ = strchr(arg+1, '=');
			if (debugflag) printf("arg+1 %s (argequ+1 %s)\n", arg+1, argequ+1);
			if (argequ != NULL) {
				int nlen = argequ - (arg+1);
				int code = encode_CA_type_string(arg+1, nlen);
				if (code >= 0)	CA[code] = grabstring(arg);
				else printf("ERROR: %s unknown\n", arg);
			}
			else printf("ERROR: %s\n", arg);
		}
//		else printf("ERROR: %s\n", arg);
		firstarg++;
	}
	if (firstarg != argc) printf("ERROR: unmatched command line argument %s\n", argv[firstarg]);
	checksettings();
	return firstarg;
}

///////////////////////////////////////////////////////////////////////////////////////////////

void showCivicValues () {
	printf("Location Civic Keys and Values:\n");
	for (int k = 0; k <= MAX_CA_TYPE; k++) {
		if (CA[k] == NULL) continue;
		printf("%3d\t%s\t(%s)\n", k, CA[k], CA_type_string(k));
	}
}

int lengthCivicValues () {	// compute number of bytes needed to encode CA values
	int nlen=0;
	for (int k = 0; k <= MAX_CA_TYPE; k++) {
		if (CA[k] == NULL) continue;
		nlen += strlen(CA[k]) + 2;	// one octet per character + key + length
	}
	return nlen;
}

char *encodeCivicString () {
	int nlen, alen, slen;
	int nbyt = 0; 
	int mlen = 0;
	int clen = 0;
	if (mapimagestring != NULL) // is there a map URL to encode ?
		mlen = strlen(mapimagestring);	
	if (mlen > 0) mlen += 3;	// add 3 bytes for subelement header
	clen = lengthCivicValues();	// are there any civic location strings to encode ?
	if (clen > 0) clen += 4;	// add 2 bytes for country code + 2 byte subelement header
	slen = clen + mlen;			// total space needed
	if (slen == 0) return NULL;	// nothing to do
	alen = 3 + slen;			// add space of 3 bytes for Measurement Report "header"
	if (traceflag) printf("clen %d mlen %d slen %d alen %d\n", clen, mlen, slen, alen);
	char *civicstr = (char *) malloc(alen * 2 + 1);	
	if (civicstr == NULL) exit(1);
	// construct "header"
	putoctet(civicstr, nbyt++, MEASURE_TOKEN);			// 1
	putoctet(civicstr, nbyt++, MEASURE_REQUEST_MODE);	// 0
	putoctet(civicstr, nbyt++, LOCATION_CIVIC_TYPE);	// 0x0b (Measurement Type Table 9-107)
	if (clen > 0) {
		putoctet(civicstr, nbyt++, LOCATION_CIVIC);		// sublement ID 
		putoctet(civicstr, nbyt++, clen-2);				// overall length
		puthexstring(civicstr, nbyt, 2, country_code);
		nbyt += 2;
		for (int k = 0; k <= MAX_CA_TYPE; k++) {
			if (CA[k] == NULL) continue;
			if (traceflag) printf("k %d CA[k] %s\n", k, CA[k]);
			nlen = strlen(CA[k]);
			while (nbyt + nlen > alen) { // should not happen
				printf("WARNING: have to extend allocation from %d bytes\n", alen);
				alen = alen * 3 / 2;
				civicstr = (char *) realloc(civicstr, alen * 2 + 1);
				if (civicstr == NULL) exit(1);
			}
			if (traceflag) printf("nbyt %d nlen %d\n", nbyt, nlen);
			putoctet(civicstr, nbyt++, k);		// key
			putoctet(civicstr, nbyt++, nlen);	// length
			puthexstring(civicstr, nbyt, nlen, CA[k]);
			nbyt += nlen;
			if (traceflag) printf("nbyt %d nlen %d\n", nbyt, nlen);
		}
	}
	if (mlen > 0) {
		putoctet(civicstr, nbyt++, MAP_IMAGE_CIVIC);	// subelement ID
		putoctet(civicstr, nbyt++, mlen-3+1);			// length
		putoctet(civicstr, nbyt++, mapmemetype);		// Map Meme Type (URL_DEFINED is default)
		if (debugflag)
			printf("mapimagestring %s (%d bytes)\n", mapimagestring, mlen-3);	// IETF RFC 3986
		puthexstring(civicstr, nbyt, mlen-3, mapimagestring);
		nbyt += mlen-3;
	}
	
	if (nbyt != alen) {
		printf("ERROR: nbyt %d alen %d\n", nbyt, alen);
	}
	civicstr[nbyt * 2] = '\0';	// null terminate
	return civicstr;
}

// TODO: check "The Civic Location field follows the little-endian octet ordering" :
// "For a given multi-octet numeric representation, the least significant octet has the lowest address."
// but there are no multioctet numbers here in CIVIC ?

void decodeCivicString(const char *str) {
	int Map_Type = 0;
	char *Map_URL = NULL;
	int nbyt=0;
	int slen = strlen(str)/2;
	if (traceflag) printf("decode %s (%d bytes)\n", str, slen);
	int a = getoctet(str, nbyt++);	// 01 MEASURE_TOKEN
	int b = getoctet(str, nbyt++);	// 00 MEASURE_REQUEST_MODE
	int c = getoctet(str, nbyt++);	// 0B (LOCATION_CIVIC_TYPE) (Measurement Type Table 9-107)
	if (a != MEASURE_TOKEN || b != MEASURE_REQUEST_MODE || c != LOCATION_CIVIC_TYPE)
		printf("ERROR: Bad Measurement Element Type %0x %0x %0x\n", a, b, c);
	while (nbyt < slen && str[nbyt] != '\0') {
		int ID = getoctet(str, nbyt++);		// ID 
		int nlen = getoctet(str, nbyt++);	// length
		if (traceflag) printf("ID %d nlen %d nbyt %d slen %d\n", ID, nlen, nbyt, slen);
		if (nbyt + nlen > slen) {	// don't try and parse past end of string
			printf("ERROR: bad length code ID %d nlen %d (nbyt %d slen %d)\n", ID, nlen, nbyt, slen);
			break;
		}
		switch(ID) {
			case LOCATION_CIVIC:
				nlen += 5;	// take into account header 
				country_code = gethexstring(str, nbyt, 2);
				nbyt += 2;
				if ((country_code[0] < 'A' || country_code[0] > 'Z') &&
					  (country_code[0] < 'a' || country_code[0] > 'z')) {
					printf("ERROR: bad country code %s\n", country_code);
				}
				else printf("\t%s\t(COUNTRY CODE)\n", country_code);
				while (nbyt < nlen && str[nbyt] != '\0') {
					if (traceflag) printf("nbyt %d nlen %d str[nbyt] %d\n", nbyt, nlen, str[nbyt]);
					ID = getoctet(str, nbyt++);		// subelement ID
					int olen = getoctet(str, nbyt++);	// subelement field length
					if (nbyt + olen > slen) {
						printf("ERROR: bad length code ID %d olen %d (nbyt %d slen %d)\n", ID, olen, nbyt, slen);
						nbyt = slen;	// force exit of outer while loop
						break;
					}
					char *text = gethexstring(str, nbyt, olen);
					nbyt += olen;
					if (traceflag) printf("%d\t%s\n", ID, text);
					if (ID >= 0 && ID <= MAX_CA_TYPE) CA[ID] = text;
				}
				showCivicValues();
				break;
				
			case MAP_IMAGE_CIVIC: 
				Map_Type = getoctet(str, nbyt++);
				Map_URL = gethexstring(str, nbyt, nlen-1);
				nbyt += nlen-1;
				printf("Map URL: %s\n", Map_URL);
				printf("Map Meme: %s\n", map_meme_type_string(Map_Type));
				break;
				
			default:
				printf("ERROR: unknown subelement ID %d (nbyt %d)\n", ID, nbyt-2);
				nbyt += nlen;
				break;
		}
	}
	if (debugflag) printf("End of decoding byte %d slen %d\n", nbyt, slen);
}

void doExample(void) {
	const char *civicstr = "01000b001d555301024d41030943616d627269646765130233322206566173736172";
	printf("-civic=%s\n", civicstr);
	decodeCivicString(civicstr);
	char *str = encodeCivicString();
	printf("-civic=%s\n", str);
	free(str);
}

/////////////////////////////////////////////////////////////////////////////////////////

void freeCivicValues () {
	for (int k = 0; k <= MAX_CA_TYPE; k++) {
		if (CA[k] == NULL) continue;
		free((void *) CA[k]);
		CA[k] = NULL;
	}
	free(CA);
	CA = NULL;
}

void initialize_arrays (void) {
	CA = (char const **) malloc((MAX_CA_TYPE+1) * sizeof(char *));	// place for civic location values
	if (CA == NULL) exit(1);
//	for (int k = 0; k <= MAX_CA_TYPE; k++) CA[k] = NULL;	// or...
	memset(CA, 0, (MAX_CA_TYPE+1) * sizeof(char *));
}

int main(int argc, const char *argv[]) {
	int firstarg = 1;

//	test_utf_unicode(0x200000); return 0;
	initialize_arrays();
	firstarg = commandline(argc, argv);

	int ncivic = lengthCivicValues();	// any command line arguments for constructing civic string?
	if (debugflag) printf("ncivic %d bytes\n", ncivic);
	if (ncivic > 0)	showCivicValues();

//	Is CIVIC string given on command line ?
	if (civicstring != NULL) {
		decodeCivicString(civicstring);
		if (checkflag) {
			printf("\n");
			ncivic = lengthCivicValues();
			char *str = encodeCivicString();
			printf("-civic=%s\n", str);
			free(str);
		}
//		return 0;
	}
//	Are arguments for constructing CIVIC string given on command line ?
	else if (ncivic > 0 || mapimagestring != NULL) { 
		char *str = encodeCivicString();
		printf("-civic=%s\n", str);
		if (checkflag) {
			printf("\n");
			decodeCivicString(str);
		}
		free(str);
//		return 0;
	}
	else if (sampleflag) doExample();

	freeCivicValues();

	return 0;
}

///////////////////////////////////////////////////////////////////////////////

// LCI element: LCI subelement, Z subelement, USAGE subelement, BSSIDS subelements.

// CIVIC element: STA location address, MAP image subelements.

///////////////////////////////////////////////////////////////////////////////

// CIVICcoder -? shows command line flags and command line value usage

///////////////////////////////////////////////////////////////////////////////

// MIT CSAIL STATA CENTER:
// CIVICcoder -state=MA -city=Cambridge -street=Vassar -number=32
// civic=01000b001d555301024d41030943616d627269646765130233322206566173736172

////////////////////////////////////////////////////////////////////////////////////////

