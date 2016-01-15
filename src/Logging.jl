module Logging

using TimeZones

import Base: show, info, warn

export debug, info, warn, err, critical, log,
       @debug, @info, @warn, @err, @error, @critical, @log,
       Logger,
       LogLevel, DEBUG, INFO, WARNING, ERROR, CRITICAL, OFF,
       LogFacility,
       SysLog

@enum LogLevel OFF=-1 CRITICAL=2 ERROR WARNING INFO=6 DEBUG

function Base.convert(::Type{LogLevel}, x::AbstractString)
    Dict("OFF"=>OFF,
         "CRITICAL"=>CRITICAL,
         "ERROR"=>ERROR,
         "WARNING"=>WARNING,
         "INFO"=>INFO,
         "DEBUG"=>DEBUG)[x]
end

@enum LogFacility LOG_KERN LOG_USER LOG_MAIL LOG_DAEMON LOG_AUTH LOG_SYSLOG LOG_LPR LOG_NEWS LOG_UUCP LOG_CRON LOG_AUTHPRIV LOG_LOCAL0=16 LOG_LOCAL1 LOG_LOCAL2 LOG_LOCAL3 LOG_LOCAL4 LOG_LOCAL5 LOG_LOCAL6 LOG_LOCAL7

abstract LogOutput

const default_log_format = "%(timestamp):%(level):%(loggername):%(msg)"
const default_syslog_format = "%(loggername):%(msg)"
const default_timestamp_format = "yyyy-mm-dd HH:MM:SS.sss"

# syslog needs a timestamp in the form: YYYY-MM-DDTHH:MM:SS.sss±TZ:TZ
const syslog_timestamp_format = "yyyy-mm-ddTHH:MM:SS.ssszzz"
const UTC = TimeZone("UTC")

default_fields() = Dict("workerid" => myid)

type SysLog <: LogOutput
    socket::UDPSocket
    ip::IPv4
    port::UInt16
    facility::LogFacility
    machine::AbstractString
    user::AbstractString
    maxlength::UInt16

    # LogOutput common attributes
    format::AbstractString
    timestamp_format::AbstractString
    timezone::TimeZone
    logging_fields::Dict

    SysLog(host::AbstractString,
           port::Int;
           facility::LogFacility=LOG_USER,
           machine::AbstractString=gethostname(),
           user::AbstractString=Base.source_path()==nothing ? "" : basename(Base.source_path()),
           maxlength::Int=1024,
           format::AbstractString=default_syslog_format,
           timestamp_format::AbstractString=default_timestamp_format,
           timezone::TimeZone=UTC,
           logging_fields::Dict=Dict()) = new(
        UDPSocket(),
        getaddrinfo(host),
        UInt16(port),
        facility,
        machine,
        user,
        UInt16(maxlength),
        format,
        timestamp_format,
        timezone,
        merge(logging_fields, default_fields())
    )

end

type LogIO <: LogOutput
    io::IO

    # LogOutput common attributes
    format::AbstractString
    timestamp_format::AbstractString
    timezone::TimeZone
    logging_fields::Dict

    LogIO(io::IO;
          format::AbstractString=default_log_format,
          timestamp_format::AbstractString=default_timestamp_format,
          timezone::TimeZone=UTC,
          logging_fields::Dict=Dict()) = new(
        io,
        format,
        timestamp_format,
        timezone,
        merge(logging_fields, default_fields())
    )
end

type Logger
    name::AbstractString
    level::LogLevel
    output::Array{LogOutput,1}
    parent::Logger

    Logger(name::AbstractString, level::LogLevel, output::LogIO, parent::Logger) = new(name, level, [output], parent)
    Logger(name::AbstractString, level::LogLevel, output::LogIO) = (x = new(); x.name = name; x.level=level; x.output=[output]; x.parent=x)
    Logger(name::AbstractString, level::LogLevel, output::Array{LogOutput,1}, parent::Logger) = new(name, level, output, parent)
    Logger(name::AbstractString, level::LogLevel, output::Array{LogOutput,1}) = (x = new(); x.name = name; x.level=level; x.output=output; x.parent=x)
end

show(io::IO, logger::Logger) = print(io, "Logger(", join([logger.name,
                                                          logger.level,
                                                          logger.output,
                                                          logger.parent.name], ","), ")")

const _root = Logger("root", WARNING, LogIO(STDERR))
Logger(name::AbstractString; kwargs...) = configure(Logger(name, WARNING, [LogIO(STDERR)], _root); kwargs...)
Logger() = Logger("logger")

write_log(syslog::SysLog, color::Symbol, msg::AbstractString) = send(syslog.socket, syslog.ip, syslog.port, length(msg) > syslog.maxlength ? msg[1:syslog.maxlength] : msg)
write_log{T<:IO}(output::T, color::Symbol, msg::AbstractString) = (println(output, msg); flush(output))
write_log(output::Base.TTY, color::Symbol, msg::AbstractString) = (Base.println_with_color(color, output, msg); flush(output))

function formatlog(format::AbstractString, logging_fields::Dict)
    function substr(s)
        v = get(logging_fields, s[3:end-1], "<none>")
        return isa(v, Function) ? string(v()) : string(v)
    end
    return replace(format, r"%\([^)]+\)", substr)
end

function formatlog(logoutput::LogOutput, level::LogLevel, loggername::AbstractString, timestamp::ZonedDateTime, msg...)
    logoutput.logging_fields["msg"] = string(msg...)
    logoutput.logging_fields["timestamp"] = Dates.format(ZonedDateTime(timestamp, logoutput.timezone), logoutput.timestamp_format)
    logoutput.logging_fields["level"] = level
    logoutput.logging_fields["loggername"] = loggername
    return formatlog(logoutput.format, logoutput.logging_fields)
end

function log(output::LogIO, level::LogLevel, color::Symbol, loggername::AbstractString, msg...)
    timestamp = TimeZones.now(UTC)
    write_log(output.io, color, formatlog(output, level, loggername, timestamp, msg...))
end

function syslog_facility_level(facility, level)
    return string("<", (UInt16(facility) << 3) + UInt16(level), ">1")
end

function log(syslog::SysLog, level::LogLevel, color::Symbol, loggername::AbstractString, msg...)
    timestamp = TimeZones.now(UTC)
    syslog_timestamp = Dates.format(timestamp, syslog_timestamp_format::AbstractString)
    message = string(syslog_facility_level(syslog.facility, level), " ",
                     syslog_timestamp, " ", syslog.machine, " ",
                     syslog.user, " - - - ",
                     formatlog(syslog, level, loggername, timestamp, msg...))
    write_log(syslog, color, message)
end

for (fn,lvl,clr) in ((:debug,    DEBUG,    :cyan),
                     (:info,     INFO,     :blue),
                     (:warn,     WARNING,  :magenta),
                     (:err,      ERROR,    :red),
                     (:critical, CRITICAL, :red))

    @eval function $fn(logger::Logger, msg...)
        if $lvl <= logger.level
            for output in logger.output
                log(output, $lvl, $(Expr(:quote, clr)), logger.name, msg...)
            end
        end
    end

    @eval $fn(msg...) = $fn(_root, msg...)

end

function configure(logger=_root; args...)
    for (tag, val) in args
        if tag == :parent
            logger.parent = parent = val::Logger
            logger.level = parent.level
            logger.output = parent.output
        end
    end

    for (tag, val) in args
        tag == :io            ? typeof(val) <: AbstractArray ? (logger.output = val) :
                                                               (logger.output = [val::LogOutput]) :
        tag == :output        ? typeof(val) <: AbstractArray ? (logger.output = val) :
                                                               (logger.output = [val::LogOutput]) :
        tag == :filename      ? (logger.output = [open(val, "a")]) :
        tag == :level         ? (logger.level  = val::LogLevel) :
        tag == :override_info ? nothing :  # handled below
        tag == :parent        ? nothing :  # handled above
                                (Base.error("Logging: unknown configure argument \"$tag\""))
    end

    logger
end

override_info(;args...) = (:override_info, true) in args

macro configure(args...)
    _args = gensym()
    quote
        logger = Logging.configure($(args...))
        if Logging.override_info($(args...))
            function Base.info(msg::AbstractString...)
                Logging.info(Logging._root, msg...)
            end
        end
        include(joinpath(Pkg.dir("Logging"), "src", "logging_macros.jl"))
        logger
    end
end

end # module
