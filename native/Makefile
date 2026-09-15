CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2
LDFLAGS = -lseccomp

all: sandbox_launcher example_target billing_tool

sandbox_launcher: sandbox_executor.cpp sandbox_filter.hpp
	$(CXX) $(CXXFLAGS) sandbox_executor.cpp -o sandbox_launcher $(LDFLAGS)

example_target: example_target.cpp sandbox_filter.hpp
	$(CXX) $(CXXFLAGS) example_target.cpp -o example_target $(LDFLAGS)

billing_tool: billing_tool.cpp sandbox_filter.hpp
	$(CXX) $(CXXFLAGS) billing_tool.cpp -o billing_tool $(LDFLAGS)

# Run standalone demo:      ./sandbox_launcher ./example_target
# Run the real billing tool: ./sandbox_launcher ./billing_tool ACC123
# unshare(CLONE_NEWNET) and seccomp both typically need CAP_SYS_ADMIN.
# Locally: sudo ./sandbox_launcher ./billing_tool ACC123
# In Docker: docker run --cap-add=SYS_ADMIN ...

clean:
	rm -f sandbox_launcher example_target billing_tool
