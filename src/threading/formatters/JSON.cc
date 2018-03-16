// See the file "COPYING" in the main distribution directory for copyright.

#include "bro-config.h"

#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

#include <sstream>
#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <iomanip>
#include <sstream>

#include "./JSON.h"
#include "../../ConvertUTF.h"
#include "./json.hpp"

using namespace threading::formatter;

JSON::JSON(MsgThread* t, TimeFormat tf) : Formatter(t), surrounding_braces(true)
	{
	timestamps = tf;
	js = new nlohmann::json;
	}

JSON::~JSON()
	{
	}

bool JSON::Describe(ODesc* desc, int num_fields, const Field* const * fields,
                    Value** vals) const
	{
	if ( surrounding_braces )
		desc->AddRaw("{");

	for ( int i = 0; i < num_fields; i++ )
		{
		const u_char* bytes = desc->Bytes();
		int len = desc->Len();

		if ( i > 0 &&
		     len > 0 &&
		     bytes[len-1] != ',' &&
		     bytes[len-1] != '{' &&
		     bytes[len-1] != '[' &&
		     vals[i]->present )
			desc->AddRaw(",");

		if ( ! Describe(desc, vals[i], fields[i]->name) )
			return false;
		}

	if ( surrounding_braces )
		desc->AddRaw("}");

	return true;
	}

bool JSON::Describe(ODesc* desc, Value* val, const string& name) const
	{
	if ( ! val->present )
		return true;

	if ( name.size() )
		{
		desc->AddRaw("\"", 1);
		desc->Add(name);
		desc->AddRaw("\":", 2);
		}

	switch ( val->type )
		{
		case TYPE_BOOL:
			//desc->AddRaw(val->val.int_val == 0 ? "false" : "true");
			js->at(name) = val->val.int_val == 0 ? false : true;
			break;

		case TYPE_INT:
			//desc->Add(val->val.int_val);
			js->at(name) = val->val.int_val;
			break;

		case TYPE_COUNT:
		case TYPE_COUNTER:
			{
			// JSON doesn't support unsigned 64bit ints.
			//if ( val->val.uint_val >= INT64_MAX )
			//	{
			//	GetThread()->Error(GetThread()->Fmt("count value too large for JSON: %" PRIu64, val->val.uint_val));
			//	desc->AddRaw("null", 4);
			//	}
			//else
			//	desc->Add(val->val.uint_val);
			js->at(name) = val->val.uint_val;
			break;
			}

		case TYPE_PORT:
			//desc->Add(val->val.port_val.port);
			js->at(name) = val->val.port_val.port;
			break;

		case TYPE_SUBNET:
			//desc->AddRaw("\"", 1);
			//desc->Add(Render(val->val.subnet_val));
			//desc->AddRaw("\"", 1);
			js->at(name) = Render(val->val.subnet_val);
			break;

		case TYPE_ADDR:
			//desc->AddRaw("\"", 1);
			//desc->Add(Render(val->val.addr_val));
			//desc->AddRaw("\"", 1);
			js->at(name) = Render(val->val.addr_val);
			break;

		case TYPE_DOUBLE:
		case TYPE_INTERVAL:
			//desc->Add(val->val.double_val);
			js->at(name) = val->val.double_val;
			break;

		case TYPE_TIME:
			{
			if ( timestamps == TS_ISO8601 )
				{
				char buffer[40];
				char buffer2[40];
				time_t the_time = time_t(val->val.double_val);
				struct tm t;

				desc->AddRaw("\"", 1);

				if ( ! gmtime_r(&the_time, &t) ||
				     ! strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &t) )
					{
					GetThread()->Error(GetThread()->Fmt("json formatter: failure getting time: (%lf)", val->val.double_val));
					// This was a failure, doesn't really matter what gets put here
					// but it should probably stand out...
					//desc->Add("2000-01-01T00:00:00.000000");
					js->at(name) = "2000-01-01T00:00:00.000000";
					}
				else
					{
					double integ;
					double frac = modf(val->val.double_val, &integ);
					snprintf(buffer2, sizeof(buffer2), "%s.%06.0fZ", buffer, frac * 1000000);
					//desc->Add(buffer2);
					js->at(name) = string(buffer2);
					}

				desc->AddRaw("\"", 1);
				}

			else if ( timestamps == TS_EPOCH )
				//desc->Add(val->val.double_val);
				js->at(name) = val->val.double_val;

			else if ( timestamps == TS_MILLIS )
				{
				// ElasticSearch uses milliseconds for timestamps and json only
				// supports signed ints (uints can be too large).
				uint64_t ts = (uint64_t) (val->val.double_val * 1000);
				if ( ts < INT64_MAX )
					//desc->Add(ts);
					js->at(name) = ts;
				else
					{
					GetThread()->Error(GetThread()->Fmt("time value too large for JSON milliseconds: %" PRIu64, ts));
					desc->AddRaw("null", 4);
					}
				}

			break;
			}

		case TYPE_ENUM:
		case TYPE_STRING:
		case TYPE_FILE:
		case TYPE_FUNC:
			{
			desc->AddRaw("\"", 1);

			js->at(name) = string(val->val.string_val.data, val->val.string_val.length);
			//nlohmann::json js = string(val->val.string_val.data, val->val.string_val.length);
			//desc->AddRaw(js.dump().c_str());

			//const UTF8* targetstart = reinterpret_cast<UTF8*>(val->val.string_val.data);
			//const UTF8* targetend = targetstart + val->val.string_val.length;
			//if ( isLegalUTF8Sequence(targetstart, targetend) )
			//	{
			//	std::ostringstream o;
			//
			//	for ( int i = 0; i < val->val.string_val.length; ++i )
			//		{
			//		char c = val->val.string_val.data[i];
			//
			//		switch (c)
			//			{
			//			case '"': o << "\\\""; break;
			//			case '\\': o << "\\\\"; break;
			//			case '\b': o << "\\b"; break;
			//			case '\f': o << "\\f"; break;
			//			case '\n': o << "\\n"; break;
			//			case '\r': o << "\\r"; break;
			//			case '\t': o << "\\t"; break;
			//			default:
			//			if (c <= '\x1f')
			//				{
			//				o << "\\u"
			//				  << std::hex << std::setw(4) << std::setfill('0') << (int)c;
			//				}
			//			else
			//				{
			//				o << c;
			//				}
			//			}
			//		}
			//
			//	desc->AddRaw(o.str().c_str(), o.str().size());
			//	}
			//else
			//	{
			//	for ( int i = 0; i < val->val.string_val.length; ++i )
			//		{
			//		char c = val->val.string_val.data[i];
			//
			//		// 2byte Unicode escape special characters.
			//		if ( c < 32 || c > 126 || c == '\n' || c == '"' || c == '\'' || c == '\\' || c == '&' )
			//			{
			//			desc->AddRaw("\\u00", 4);
			//			char hex[2] = {'0', '0'};
			//			bytetohex(c, hex);
			//			desc->AddRaw(hex, 1);
			//			desc->AddRaw(hex + 1, 1);
			//			}
			//		else
			//			{
			//			desc->AddRaw(&c, 1);
			//			}
			//		}
			//	}

			desc->AddRaw("\"", 1);
			break;
			}

		case TYPE_TABLE:
			{
			desc->AddRaw("[", 1);

			for ( int j = 0; j < val->val.set_val.size; j++ )
				{
				if ( j > 0 )
					desc->AddRaw(",", 1);

				Describe(desc, val->val.set_val.vals[j]);
				}

			desc->AddRaw("]", 1);
			break;
			}

		case TYPE_VECTOR:
			{
			desc->AddRaw("[", 1);

			for ( int j = 0; j < val->val.vector_val.size; j++ )
				{
				if ( j > 0 )
					desc->AddRaw(",", 1);
				Describe(desc, val->val.vector_val.vals[j]);
				}

			desc->AddRaw("]", 1);
			break;
			}

		default:
			return false;
		}

	return true;
	}

threading::Value* JSON::ParseValue(const string& s, const string& name, TypeTag type, TypeTag subtype) const
	{
	GetThread()->Error("JSON formatter does not support parsing yet.");
	return NULL;
	}

void JSON::SurroundingBraces(bool use_braces)
	{
	surrounding_braces = use_braces;
	}
