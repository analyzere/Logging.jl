module TestHierarchy

using Base.Test
using Logging
using Logging: LogIO

# configure root logger
Logging.configure(level=DEBUG)
root = Logging._root


loggerA = Logger("loggerA")
loggerB = Logger("loggerB", WARNING, [LogIO(STDOUT),LogIO(STDERR)])

# test hierarchy
@test root.parent == root
@test loggerA.parent == root
@test loggerB.parent == loggerB

end
