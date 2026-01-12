## Common Field Names

| Field | Description |
|-------|-------------|
| `@timestamp` | Time of event |
| `event_simpleName` | Event type (e.g., `ProcessRollup2`, `PeFileWritten`) |
| `event_platform` | Platform type (Win, Mac, Linux) |
| `host` | Hostname of endpoint |
| `UserName` | Logged-in user |
| `CommandLine` | Full command line of executed process |
| `Image` | Path to the binary |
| `ParentCommandLine` | Command line of parent process |
| `ParentBaseFileName` | Parent process name |
| `GrandparentCommandLine` | Grandparent command line |
| `FileName` | File name of artifact |
| `FilePath` | Full path of artifact |
| `SHA256HashData` | SHA256 file hash |
| `RemoteIP` | Destination IP address |
| `ScriptContent` | Contents of script (if detected) |
| `ScriptContentName` | Name of embedded script |

### CS Simple name for events:
`#event_simpleName=%SIMPLENAME%`

#### Group Output (splunk dedup):

	| groupBy([])
	
	| groupBy([Field], function=([collect([Field, Field])]), limit=max)

#### Table output(field names by csv)
`| table([])`


#### Count  
`|  _count <5

## Timestamp
| timestamp := formatTime("%Y-%m-%d %H:%M:%S", field=timestamp, locale=en_US, timezone="Europe/London")

## Execution Chain
	| ExecutionChain:=format(format="%s\n\t└ %s (%s)", field=[ParentBaseFileName, FileName, RawProcessId])

### Process Lineage
	//Create process lineage tree
	| ProcessLineage:=format(format="%s\n\t└ %s %s\n\t\t └ %s", field=[GrandParentBaseFileName, ParentBaseFileName, BaseFileName ])

# asn

The `asn` function takes a field that contains an IP address and adds Autonomous System Number (ASN) data to the query results. The added data includes the ASN identifier and ASN organization.

```
| asn(RemoteAddressIP4)
| select([RemoteAddressIP4, RemoteAddressIP4.asn, RemoteAddressIP4.org])
```

[asn Documentation](https://library.humio.com/data-analysis/functions-asn.html)

---

# assignment operator

The assignment operator (`:=`) sets the value of a specified field to a value or the result of a formula. You can use the operator `:=` with functions that take an `as` parameter.

```
| timeDeltaSeconds := (now()*1000)-ProcessStartTime
```

[Assignment Operator Documentation](https://library.humio.com/data-analysis/syntax-fields.html#syntax-fields-assignment-operator)

---

# bucket

The `bucket` function divides the search time interval into buckets. Each event is put into a bucket based on its timestamp value.

Events are grouped by their bucket, generating the field `_bucket`. The value of `_bucket` is the corresponding bucket's start time in milliseconds (UTC time).

The `bucket()` function takes all the same parameters as `groupBy()`.

```
| bucket(1day, field=[RFMState], function=(count(field=aid, as="endpointCount")))
```

Example in counting RFM Linux systems by day:

```
#event_simpleName=OsVersionInfo RFMState=*
| day := formatTime("%Y-%m-%d", field=@timestamp, locale=en_US, timezone=Z)
| groupBy([aid, day], function=(selectLast([RFMState, @timestamp])), limit=max)
| RFMState match {
	1 => RFMState := "RFM" ;
	0 => RFMState := "OK" ;
	}
| bucket(1day, field=[RFMState], function=(count(field=aid, as="endpointCount")))
| _bucket := formatTime("%Y-%m-%d", field=_bucket, locale=en_US, timezone=Z)
```

[bucket Documentation](https://library.humio.com/data-analysis/functions-bucket.html)


---

# case

Using `case` expressions, you can describe alternative flows in your queries. It is similar to `case` or `cond` you might know from many other functional programming languages. It essentially allows you to write `if-then-else` constructs that work on events streams.

Destructive Case Statement

```
| case {
	UserIsAdmin=1 | UserIsAdmin := "True" ;
	UserIsAdmin=0 | UserIsAdmin := "False" ;
	*; 
}
```

Non-Destructive Case Statement

```
| case {
	UserIsAdmin=1 | _UserIsAdmin := "True" ;
	UserIsAdmin=0 | _UserIsAdmin := "False" ;
	*; 
}
```
 
[case Documentation](https://library.humio.com/data-analysis/syntax-conditional.html#syntax-conditional-case)


---

# cidr

The `cidr` function filters events using CIDR subnets.

```
| !cidr(RemoteAddressIP4, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1/32", "169.254.0.0/16", "0.0.0.0/32"])
```

[cidr Documentation](https://library.humio.com/data-analysis/functions-cidr.html)


---

# concat

The `concat` function concatenates the values of a list of fields into a value in a new field.

```
| concat([UID, UserSid], as="userIdentifier")
```

[concat Documentation](https://library.humio.com/data-analysis/functions-concat.html)


---

# concatArray

The `concatArray` function concatenates the values of all fields with the same name and an array suffix into a value in a new field. Such array fields typically come as output from either `parseJson()` or `splitString()`.

All array fields starting with index from and ending with index to are selected. If an index is missing, the concatenation stops with the previous index, thus if only index `0`, `1` and `3` are present, only index `0` and `1` are concatenated. If the first index is missing, no field is added to the event.

```
#event_simpleName=DnsRequest
| splitString(IP4Records, by=";", as=IP4RecordsSplit)
| concatArray(IP4RecordsSplit, as=IP4RecordsMV, separator="\n")
| groupBy([DomainName], function=([collect([IP4RecordsMV]), count(IP4RecordsMV, distinct=true)]))
| test(_count>0)
```

[concatArray Documentation](https://library.humio.com/data-analysis/functions-concatarray.html)


---

# correlate

The `correlate()` function looks for patterns across given search parameters.

In the example below, correlate looks for the commands whoami, net, and systeminfo  being run on the same system within a 5 minute time interval. The `sequence` parameter is set to `false` indicating that the ordering of the events does not matter.

```
correlate(
    whoami: {
        #repo="base_sensor" #event_simpleName=ProcessRollup2 event_platform=Win FileName="whoami.exe" 
    } include: [aid, ComputerName, FileName],
    net: {
        #repo="base_sensor" #event_simpleName=ProcessRollup2 event_platform=Win FileName=/^net1?\.exe$/
          | aid <=> whoami.aid
          } include: [aid, ComputerName, FileName],
    systeminfo: {
        #repo="base_sensor" #event_simpleName=ProcessRollup2 event_platform=Win FileName="systeminfo.exe"
          | aid <=> net.aid
          } include: [aid, ComputerName, FileName],
sequence=false, within=5m)
```

[correlate documentation](https://library.humio.com/data-analysis/functions-correlate.html)

---

# count

The `count` function counts the number of events in the repository, or streaming through the function. The result is put in a field named, `_count`. You can use this field name to pipe the results to other query functions or for general use.

It is possible to specify a field and only events containing that field are counted. It is also possible to output a distinct count. 

Count

```
| count(FileName, as=executionCount)
```

Distinct Count

```
| count(aid, distinct=true, as=uniqueEndpoints)
```

[count Documentation](https://library.humio.com/data-analysis/functions-count.html)


---

# createEvents

The `createEvents()` query function generates temporary events as part of the query and is ideal for generating sample data for testing or troubleshooting. It is regarded as an aggregator function and, therefore, discards all incoming events and outputs the generated ones. The events are generated with no extracted fields but `createEvents()` can be combined with one of the many parsers. For example, given raw strings in the format of key-value pairs, the pairs can be parsed to fields using the `kvParse()` function.

```
createEvents(["Shape=Square, Color=Red", "Shape=Circle, Color=Blue", "Shape=Triangle, Color=Green"])
```

With field parsing:

```
createEvents(["Shape=Square, Color=Red", "Shape=Circle, Color=Blue", "Shape=Triangle, Color=Green"])
| kvParse()
```

[createEvents Documentation](https://library.humio.com/data-analysis/functions-createevents.html)


---

# default

The `default`  function creates a field with the name of the parameter `field` setting its value to `value`. If the field already exists on an event the field keeps its existing value.

```
| default(value="Unknown", field=[GrandParentBaseFileName, ParentBaseFileName], replaceEmpty=true)
```

Of note, while `replaceEmpty=true` is optional, it is necessary to populate files that are listed as `<empty_string>`.


[default Documentation](https://library.humio.com/data-analysis/functions-default.html)


---

# defineTable

defineTable executes a subquery that generates an in-memory, ad-hoc table based on its results. The ad-hoc table can be joined with the results of the primary query using the [[match]] function.

```
defineTable(
    query={ #event_simpleName=ZipFileWritten
    }, include=[ContextProcessId,TargetFileName,aid],name="zip_file_writes")
| #event_simpleName=ProcessRollup2
| match(table="zip_file_writes",field=[aid, TargetProcessId], column=[aid, ContextProcessId])
| table([@timestamp,ComputerName,FileName, CommandLine, TargetFileName], limit=1000)
| rename([[FileName,WritingFile], [CommandLine, WritingCmdLine], [TargetFileName, WrittenFile]])
```

[defineTable documentation](https://library.humio.com/data-analysis/functions-definetable.html)


---

# drop

The `drop` function allows you remove attributes and columns from a result set.

```
| drop([eventCount, cid])
```

[drop Documentation](https://library.humio.com/data-analysis/functions-drop.html)


---

# format - concat

The `concat` query function is used to format a string using `printf` style. The formatted string is put in a new field. The input parameters or fields can be one field or an array of fields. See also: [[concat]].

```
| format(format="%s > %s > %s { %s }", field=[GrandParentBaseFileName, ParentBaseFileName, fileName, CommandLine], as="processLineage")
```

[format Documentation](https://library.humio.com/data-analysis/functions-format.html#query-function-format-format-format)


---

# format - field conversions


```
| Status_hex := format(field=Status, "%x")
```

[format Documentation](https://library.humio.com/data-analysis/functions-format.html#query-function-format-format-format)


---

# format - hyperlinks

```
rootURL  := "https://falcon.crowdstrike.com/" ;
//rootURL  := "https://falcon.laggar.gcw.crowdstrike.com/" ;
//rootURL  := "https://falcon.eu-1.crowdstrike.com/" ;
//rootURL  := "https://falcon.us-2.crowdstrike.com/" ;
 

// Make writing the URL a bit easier. 
| colon := "%3A"
| tick  := "%27"
| plus  := "%2B"

// Virus Total
| format("[Virus Total](https://www.virustotal.com/gui/file/%s)", field=[SHA256HashData], as="VT")

// Hybrid Analysis
| format("[Hybrid Analysis](https://www.hybrid-analysis.com/search?query=%s)", field=[SHA256HashData], as="HA")

// Intelligence Graph
| format("[Indicator Graph](%sintelligence/graph?indicators=hash%s%s%s%s)", field=["rootURL", "colon", "tick", "SHA256HashData", "tick"], as="Indicator Graph")
```

```
// Graph Explorer
| rootURL  := "https://falcon.crowdstrike.com/" /* US-1 */
//| rootURL  := "https://falcon.us-2.crowdstrike.com/" /* US-2 */
//| rootURL  := "https://falcon.laggar.gcw.crowdstrike.com/" /* Gov */
//| rootURL  := "https://falcon.eu-1.crowdstrike.com/"  /* EU */
| format("[Graph Explorer](%sgraphs/process-explorer/graph?id=pid:%s:%s)", field=["rootURL", "aid", "falconPID"], as="Graph Explorer") 
```

[format Documentation](https://library.humio.com/data-analysis/functions-format.html#functions-format-examples)



---

# format - rounding numbers

The following takes a field that contains and integer and rounds it to two decimal places. The value `2f` can be changed to the number of decimal places desired. If no decimal places are required, consider using the [[round]] function:

```
| FileSizeMB:=(Size/1024/1024)
| format("%,.2f",field=["FileSizeMB"], as="FileSize")
```

Rounding with a unit indicator:

```
| FileSizeMB:=(Size/1024/1024)
| format("%,.2f MB",field=["FileSizeMB"], as="FileSize")
```

[format Documentation](https://library.humio.com/data-analysis/functions-format.html#functions-format-examples)


---

# formatDuration

The `formatDuration` function will convert a duration into a human readable string. The `from` parameter can be set to your duration's magnitude.

|   |   |   |
|---|---|---|
|**Valid Values**|`d`|Days|
||`h`|Hours|
||`m`|Minutes|
||`ms`|Milliseconds|
||`ns`|Nanoseconds|
||`s`|Seconds|
||`us`|Microseconds|

```
| formatDuration(timeDelta, from=ms, precision=4, as=timeDelta)
```

[formatDuration Documentation](https://library.humio.com/data-analysis/functions-formatduration.html)


---

# formatTime

The `formatTime()` function formats times using a subset of the [Java Formatter pattern](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/util/Formatter.html#dt) format. The following formats are supported:

|Symbol|Description|Example|
|---|---|---|
|`%H`|Hour of the day for the 24-hour clock, formatted as two digits with a leading zero as necessary.|00, 23|
|`%I`|Hour for the 12-hour clock, formatted as two digits with a leading zero as necessary.|01, 12|
|`%k`|Hour of the day for the 24-hour clock.|0, 23|
|`%l`|Hour for the 12-hour clock.|1, 12|
|`%M`|Minute within the hour formatted as two digits with a leading zero as necessary.|00, 59|
|`%S`|Seconds within the minute, formatted as two digits with a leading zero as necessary.|00, 60 (leap second)|
|`%L`|Millisecond within the second formatted as three digits with leading zeros as necessary.|000 - 999|
|`%N`|Nanosecond within the second, formatted as nine digits with leading zeros as necessary.|000000000 - 999999999|
|`%p`|Locale-specific morning or afternoon marker in lower case.|am, pm|
|`%z`|RFC 822 style numeric time zone offset from GMT.|-0800|
|`%Z`|A string representing the abbreviation for the time zone.|UTC, EAT|
|`%s`|Seconds since the beginning of the epoch starting at 1 January 1970 00:00:00 UTC (UNIXTIME)|1674304923|
|`%Q`|Milliseconds since the beginning of the epoch starting at 1 January 1970 00:00:00 UTC|1674304923001.|
|`%B`|Locale-specific full month name.|"January", "February"|
|`%b`|Locale-specific abbreviated month name.|"Jan", "Feb"|
|`%h`|Same as 'b'.|"Jan", "Feb"|
|`%A`|Locale-specific full name of the day of the week.|"Sunday", "Monday"|
|`%a`|Locale-specific short name of the day of the week.|"Sun", "Mon".|
|`%C`|Four-digit year divided by 100, formatted as two digits with leading zero as necessary|00, 99|
|`%Y`|Year, formatted as at least four digits with leading zeros as necessary.|0092, 2023|
|`%y`|Last two digits of the year, formatted with leading zeros as necessary.|00, 23|
|`%j`|Day of year, formatted as three digits with leading zeros as necessary.|001 - 366|
|`%m`|Month, formatted as two digits with leading zeros as necessary.|01 - 13|
|`%d`|Day of month, formatted as two digits with leading zeros as necessary.|01 - 31|
|`%e`|Day of month, formatted as two digits.|1 - 31|
|`%R`|Time formatted as "%H:%M".|23:59|
|`%T`|Time formatted as "%H:%M:%S".|23:59:59|
|`%r`|Time formatted as "%I:%M:%S %p". NOTE: AM and PM will be uppercase unlike for %p.|01:21:11 PM|
|`%D`|Date formatted as "%m/%d/%y".|01/31/23|
|`%F`|ISO 8601 complete date formatted as "%Y-%m-%d"|1989-06-04|
|`%c`|Date and time formatted as "%a %b %d %T %Z %Y"|Thu Feb 02 11:03:28 Z 2023|

```
| formatTime(format="%Y-%m-%d %H:%M:%S.L", field=firstLogon, as="firstLogon")
```

[formatTime Documentation](https://library.humio.com/data-analysis/functions-formattime.html)


---

# geoHash

The `geoHash` function calculates a geohash value given two fields representing latitude and longitude. Precision can be set from to values from 1 (least precise) to 12 (most precise).

```
| geoHash := geohash(lat=OriginSourceIpAddress.lat, lon=OriginSourceIpAddress.lon, precision=2)
```

[geoHash Documentation](https://library.humio.com/data-analysis/functions-geohash.html) | [geohash information (Wikipedia)](https://en.wikipedia.org/wiki/Geohash)



---

# groupBy

The `groupBy()` query function is used to group together events by one or more specified fields. This is similar to the `GROUP BY` method in SQL databases. Further, it can be used to execute aggregate functions on each group. The results are returned in the `_field` parameter for each aggregate function. For example, the `_count` field if the [`count()`](https://library.humio.com/data-analysis/functions-count.html "Counts given events.      (click for more information)") function is used.

```
| groupBy([aid, UserSid], function=([count(aid, as=exeuctionCount), collect([CommandLine])]), limit=max)
```

[groupBy Documentation](https://library.humio.com/data-analysis/functions-groupby.html)


---

# head

The `head` function returns a limited number of events, starting with the oldest. This function is equivalent to the command-line `head` tool.

```
| head(5)
```

[head Documentation](https://library.humio.com/data-analysis/functions-head.html)


---

# in

The `in` function may be used to select events in which the given field contains particular values. For instance, you might want to monitor events in which log messages contain `error`, `warning`, or other similar words in log entries, or numeric values in other fields.

```
| in(LogonDomain, values=["acme.com","beta.com"])
```

```
| in(LogonType, values=[2,10])
```

[in Documentation](https://library.humio.com/data-analysis/functions-in.html)


---

# ipLocation

The `ipLocation` function determines the country, city, longitude, and latitude for an IP address (ipv4 or ipv6). The attributes `ip.country`, `ip.city, ip.lon`, `ip.lat` are added to the event.

```
| ipLocation(RemoteAddressIP4)
```

Example of using ipLocation with pre-filtering for RFC-1819 addresses:

```
| !cidr(RemoteAddressIP4, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1/32", "169.254.0.0/16", "0.0.0.0/32"])
| ipLocation(RemoteAddressIP4)
```

[ipLocation Documentation](https://library.humio.com/data-analysis/functions-iplocation.html)


---

# join

Joins two LogScale searches. When joining two searches, you need to define the keys/fields that are used to match up results. This is done using the [`_field=name`](https://library.humio.com/data-analysis/functions-join.html#query-function-join-join-field "parameter to join():  Specifies which field in the event (log line) must match the given column value.  (click for more information)") or [`_field=[name,name,...`](https://library.humio.com/data-analysis/functions-join.html#query-function-join-join-field "parameter to join():  Specifies which field in the event (log line) must match the given column value.  (click for more information)") parameter.

```
| join({#event_simpleName=/^(UserIdentity|UserLogon)$/ | UserName!=/(\$$|^DWM-|LOCAL\sSERVICE|^UMFD-|^$)/}, field=UserSid, include=UserName, mode=left)
```

```
#event_simpleName=ProcessRollup2
| ImageFileName=/(?<FilePath>(\/|\\).+(\/|\\))(?<FileName>.+$)/
| FileName=~wildcard(?FileName, ignoreCase=true)
| select([aid, ComputerName, UserSid, UserName, FilePath, FileName, CommandLine])
| join({#event_simpleName=/^(UserIdentity|UserLogon)$/ | UserName!=/(\$$|^DWM-|LOCAL\sSERVICE|^UMFD-|^$)/}, field=UserSid, include=UserName, mode=left)
| UserName=~wildcard(?UserName, ignoreCase=true)
```

[join Documentation (1)](https://library.humio.com/data-analysis/functions-join.html) | [join Documenation (2)](https://library.humio.com/data-analysis/syntax-joins.html)



---

# kvParse

The function `kvParse` is used to parse key-values of the form:

- `key=value`
- `key="value"`
- `key='value'`
- `key = value`

Both key and value can be either quoted using `"` or `'`, or unquoted.

```
createEvents(["Shape=Square, Color=Red", "Shape=Circle, Color=Blue", "Shape=Triangle, Color=Green"])
| kvParse()
```

[kvParse Documentation](https://library.humio.com/data-analysis/functions-kvparse.html)


---

# length

The `length` function returns the number of characters in a string field.

```
| length("CommandLine", as="cmdLength")
```

[length Documentation](https://library.humio.com/data-analysis/functions-length.html)


---

# lower

The `lower` function will change the text given, by way of a field from an event or otherwise, to all lower-case letters. This is based on the presumed language, but you can set the language and locale if needed.

```
| lowerImageFileName := lower(ImageFileName)
```

[lower Documentation](https://library.humio.com/data-analysis/functions-lower.html)

---

# match (lookup)

Matches a value in the CSV or through a limited form of JSON file, uploaded using Lookup Files.

```
| match(file="fdr_aidmaster.csv", field=aid, include=ComputerName, ignoreCase=true, strict=false)
```

to output all columns of a lookup:

```
| aid =~ match(file="fdr_aidmaster.csv", column=aid, strict=false)
```

```
| cid =~ match(file="cid_name.csv", column=cid, strict=true)
```

[match Dcoumentation](https://library.humio.com/data-analysis/functions-match.html)


---

# match

Using `match` expressions, you can describe alternative flows in your queries where the conditions all check the same field. It is similar to the `switch` operation you might recognize from many other programming languages. It essentially enables you to write `if-then-else` constructs that work on events streams.

Destructive

``` 
| UserIsAdmin match {
	1 => UserIsAdmin := "True" ;
	0 => UserIsAdmin := "False" ;
}
```

Non-Destructive

```
| UserIsAdmin match {
	1 => _UserIsAdmin := "True" ;
	0 => _UserIsAdmin := "False" ;
}
```

[match Documentation](https://library.humio.com/data-analysis/syntax-conditional.html#syntax-conditional-match)


---

# parseJson

The `parseJason` function parses data as JSON. Specify `field=@rawstring` to parse the rawstring into JSON. It is possible to prefix the names of the extracted fields using the prefix parameter.

```
| replace(regex="\"SHA1HashData\":\"0000000000000000000000000000000000000000\",", with="", field=@rawstring, as=@rawstring)
| parseJson(@rawstring)
```

[parseJson Documentation](https://library.humio.com/data-analysis/functions-parsejson.html)


---

# parseXml

The `parseXml` function will parse data as XML. Specify `field=@rawstring` to parse the `@rawstring` into XML. If the specified field does not exist, the event is skipped. If the specified field exists but contains non-XML data, the behaviors depends on the strict parameter.

```
#event_simpleName=ScheduledTaskRegistered
| parseXml(field=TaskXml)
| Task.Principals.Principal.UserId=*
| Task.Principals.Principal.UserId!=/^S-1-5-(18|20)$/
| select([aid, UserName, TaskName, TaskExecArguments, Task.Principals.Principal.RunLevel, Task.Principals.Principal.UserId, Task.Settings.Hidden, Task.Settings.Priority])
```

[parseXML Documentation](https://library.humio.com/data-analysis/functions-parsexml.html)


---

# rdns

The `rdns` function resolves hostnames using reverse DNS lookups.

If a lookup fails, it will keep the event but not add the given field.

The number of resulting events from this function is limited by the configuration parameter [`MAX_STATE_LIMIT`](https://library.humio.com/falcon-logscale-self-hosted/envar-max-state-limit.html), whose default limit is 20000. If the number of events exceeds this limit, the result will be truncated with a warning.

To prevent the `rdns` function from blocking query execution for an indeterminate amount of time, a timeout is applied to all RDNS requests. If an RDNS request doesn't return a result within the timeout, the lookup is considered to have failed for the associated event. However, if the request eventually returns, its result is added to an internal cache within LogScale for a period of time. Therefore, a static query using the `rdns` function may fail a lookup for an event on its first execution, but succeed in a subsequent execution. In live queries this behaviour is less of a problem, as the `rdns` function will be evaluated continually. Thus, it is preferable to mainly use the `rdns` function in live queries.

```
| rdns(RemoteAddressIP4, as=rdns)
| select([RemoteAddressIP4, rdns])
```

[rdns Documentation](https://library.humio.com/data-analysis/functions-rdns.html)


---

# readFile

The `readFile` function reads the contents of a lookup file.

```
readFile("falcon/investigate/AsepClass.csv")
```

[readFile Documentation](https://library.humio.com/data-analysis/functions-readfile.html)


---

# regex - extraction via capture

```
| ImageFileName=/Device\\HarddiskVolume\d+(?<FilePath>\\.+\\)(?<FileName>.+)$/i
```

Example of extracting file name and file path from ImageFileName:

```
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/Device\\HarddiskVolume\d+(?<FilePath>\\.+\\)(?<FileName>.+)$/i
| select([FileName, FilePath, ImageFileName])
```

[regex Documentation](https://library.humio.com/data-analysis/functions-regular-expression.html)


---

# regex

The `regex` function both works as a filter and can extract new fields using a regular expression. The regular expression can contain one or more named capturing groups. Fields with the names of the groups will be added to the events.

Inline

```
ImageFileName=/\\powershell\.exe/i
```

Function with Strict Matching

```
| regex("(sc|net1?)\s+(?<netFlag>\S+)\s+", field=CommandLine, strict=true)
```

Function with Non-Strict Matching

```
| regex("(sc|net1?)\s+(?<netFlag>\S+)\s+", field=CommandLine, strict=false)
```

The [`regex()`](https://library.humio.com/data-analysis/functions-regex.html "regex()") function provides similar functionality to the `/regex/` syntax, however, the [`regex()`](https://library.humio.com/data-analysis/functions-regex.html "regex()") function searches specific fields (and only [@rawstring](https://library.humio.com/data-analysis/searching-data-event-fields.html#searching-data-event-fields-metadata-rawstring) by default). In contrast, the `/regex/` syntax searches _all_ sent and parsed fields and [@rawstring](https://library.humio.com/data-analysis/searching-data-event-fields.html#searching-data-event-fields-metadata-rawstring).

If you specify a field with the `/regex/` syntax, the search is limited only to those field, for example:

```
| ImageFileName = /powershell/
```

Limits the search to only the specified field.

The difference in search scope between the two regex syntax operations introduces a significant performance difference between the two. Using [`regex()`](https://library.humio.com/data-analysis/functions-regex.html "regex()") searches only the specified field ([@rawstring](https://library.humio.com/data-analysis/searching-data-event-fields.html#searching-data-event-fields-metadata-rawstring) by default) and can be significantly more performant than the `/regex/` syntax depending on the number of fields in the dataset.

[regex Documentation](https://library.humio.com/data-analysis/functions-regular-expression.html)


---

# rename

The `rename` function renames a field.

```
| rename(aid, as="Falcon Agent ID")
```

the `rename` function can also accept arrays:

```
| rename([[ComputerName, Endpoint], [UserName, User]])
```

[rename Documentation](https://library.humio.com/data-analysis/functions-rename.html)


---

# replace

The `replace` function replaces each substring of the specified fields value that matches the given regular expression with the given replacement.

```
| replace(regex=^apples$, with=oranges)
```

```
| ip =~replace(".", with="")
```

[replace Documentation](https://library.humio.com/data-analysis/functions-replace.html)


---

# round

The `round` function rounds a numeric input field to the nearest integer, with an optional method to set the rounding type.

```
| roundNumber:=round(number)
```

Example:

```
createEvents(["Number=1.2", "Number=1.23", "Number=1.234","Number=1.2345","Number=1.789"])
| kvParse()
| roundNumber:=round(Number)
| select([Number, roundNumber])
```

Please note that `round` will convert to the nearest whole integer. To round numbers with decimal-point precision, use `format`.

[round Documentation](https://library.humio.com/data-analysis/functions-round.html) | [round Examples](https://library.humio.com/data-analysis/functions-round.html#functions-round-examples) | [[format - rounding numbers]]



---

# search

Additional searches can be leveraged in LogScale by simply adding another pipe (`|`) to the query syntax. Example:

```
event_platform=Mac event_simpleName=UserLogon
| UserName="Andrew"
| UserSid!=S-1-5-18
| UserIsAdmin=1
```


---

# select

```
| select([@timestamp, aid, UserSid, ImageFileName, CommandLine])
```

[select Documentation](https://library.humio.com/data-analysis/functions-select.html)


---

# selfJoinFilter

```
| selfJoinFilter([aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=DnsRequest}], prefilter=true)
```

Example usage to merge events:

```
event_platform=Win #event_simpleName=/^(ProcessRollup2|DnsRequest)$/
| falconPID := TargetProcessId
| falconPID := ContextProcessId
| selfJoinFilter([aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=DnsRequest}], prefilter=true)
| groupBy([aid, falconPID], function=([count(#event_simpleName, distinct=true, as=eventCount), collect([ParentBaseFileName, ImageFileName, CommandLine])]))
| test(eventCount==2)
```

[selfJoinFilter Documentation](https://library.humio.com/data-analysis/functions-selfjoinfilter.html)


---

# sort

```
| sort(ImageFileName, order=asc, limit=100)
```

[sort Documentation](https://library.humio.com/data-analysis/functions-sort.html)


---

# splitString

```
| splitString(field=CommandLine, by=",", as=CommandLine)
| split(CommandLine)
```

[splitString Documentation](https://library.humio.com/data-analysis/functions-splitstring.html)
[split Documentation](https://library.humio.com/data-analysis/functions-split.html)

Additional option to split a multi-value, comma separated field using regex:

```
| CommandLine=/(?<CommandLine>[^,]+)/g
| groupBy([CommandLine])
```

[regex Field Extraction Documentation](https://library.humio.com/data-analysis/syntax-fields.html#syntax-fields-extracting)


---

# table

```
| table([@timestamp, aid, UserSid, ImageFileName, CommandLine])
```

[table Documentation](https://library.humio.com/data-analysis/functions-table.html)


---

# tail

Note: the function `tail` returns a limited number of events, starting with the **newest**. This function is equivalent to the command-line `tail` tool.

```
| tail(5)
```

[tail Documentation](https://library.humio.com/data-analysis/functions-tail.html)


---

# test

```
| test(logonCount<5)
```

[test Documentation](https://library.humio.com/data-analysis/functions-test.html)


---

# timeChart

```
| timeChart(LogonType, function=count(aid),span=1d)
```

[timeChart Documentation](https://library.humio.com/data-analysis/functions-timechart.html)


---

# top

```
#event_simpleName=UserLogon UserSid=/S-1-5-21-/
| top([UserName], limit=100)
```

[top Documentation](https://library.humio.com/data-analysis/functions-top.html)

---

