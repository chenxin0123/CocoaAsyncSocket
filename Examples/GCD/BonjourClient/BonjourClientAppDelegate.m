#import "BonjourClientAppDelegate.h"
#import "GCDAsyncSocket.h"
#import "DDLog.h"
#import "DDTTYLogger.h"
#import "DDASLLogger.h"
#import <arpa/inet.h>
#import <fcntl.h>
#import <ifaddrs.h>
#import <netdb.h>
#import <netinet/in.h>
#import <net/if.h>
#import <sys/socket.h>
#import <sys/types.h>
#import <sys/ioctl.h>
#import <sys/poll.h>
#import <sys/uio.h>
#import <sys/un.h>
#import <unistd.h>

// Log levels: off, error, warn, info, verbose
static const int ddLogLevel = LOG_LEVEL_VERBOSE;

@interface BonjourClientAppDelegate (Private)
- (void)connectToNextAddress;
@end

#pragma mark -

@interface BonjourClientAppDelegate ()

@property (nonatomic, strong) NSMutableArray *array;///<

@end

@implementation BonjourClientAppDelegate

@synthesize window;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
	// Configure logging framework
	
	[DDLog addLogger:[DDTTYLogger sharedInstance]];
	
	// Start browsing for bonjour services
	
	netServiceBrowser = [[NSNetServiceBrowser alloc] init];
	
	[netServiceBrowser setDelegate:self];
//    [netServiceBrowser searchForRegistrationDomains];
	[netServiceBrowser searchForServicesOfType:@"_YourServiceName._tcp." inDomain:@"local."];
    
    _array = [NSMutableArray array];
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)sender didNotSearch:(NSDictionary *)errorInfo
{
	DDLogError(@"DidNotSearch: %@", errorInfo);
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)sender
           didFindService:(NSNetService *)netService
               moreComing:(BOOL)moreServicesComing
{
	DDLogVerbose(@"DidFindService: %@", [netService name]);
	
	// Connect to the first service we find
	
	if (serverService == nil)
	{
		DDLogVerbose(@"Resolving...");
		
        [_array addObject:netService];
		[netService setDelegate:self];
		[netService resolveWithTimeout:5.0];
	}
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)sender
         didRemoveService:(NSNetService *)netService
               moreComing:(BOOL)moreServicesComing
{
	DDLogVerbose(@"DidRemoveService: %@", [netService name]);
}

- (void)netServiceBrowserDidStopSearch:(NSNetServiceBrowser *)sender
{
	DDLogInfo(@"DidStopSearch");
}

- (void)netService:(NSNetService *)sender didNotResolve:(NSDictionary *)errorDict
{
	DDLogError(@"DidNotResolve");
}

- (void)netServiceDidResolveAddress:(NSNetService *)sender
{
	DDLogInfo(@"DidResolve: %@", [sender addresses]);
	
	if (serverAddresses == nil)
	{
		serverAddresses = [[sender addresses] mutableCopy];
	}
	
	if (asyncSocket == nil)
	{
		asyncSocket = [[GCDAsyncSocket alloc] initWithDelegate:self delegateQueue:dispatch_get_main_queue()];
		
		[self connectToNextAddress];
	}
    [self outputHosts:sender];
}
- (void)outputHosts:(NSNetService *)netService {
    NSArray<NSData *> *addresses = [netService addresses];
    for (NSData *addr in addresses) {
        NSString *s = nil;
        const struct sockaddr *sa = (typeof(sa))[addr bytes];
        if (sa->sa_family == AF_INET) {
            struct sockaddr_in sockaddr4;
            memcpy(&sockaddr4, sa, sizeof(sockaddr4));
            char addrBuf[16];
            
            if (inet_ntop(AF_INET, &sockaddr4.sin_addr, addrBuf, (socklen_t)sizeof(addrBuf)) == NULL)
            {
                addrBuf[0] = '\0';
            }
            s = [NSString stringWithCString:addrBuf encoding:NSASCIIStringEncoding];
            NSLog(@"ipv4 host %@",s);
        } else {
            struct sockaddr_in6 sockaddr6;
            memcpy(&sockaddr6, sa, sizeof(sockaddr6));
            char addrBuf[16];
            
            if (inet_ntop(AF_INET, &sockaddr6.sin6_addr, addrBuf, (socklen_t)sizeof(addrBuf)) == NULL)
            {
                addrBuf[0] = '\0';
            }
            s = [NSString stringWithCString:addrBuf encoding:NSASCIIStringEncoding];
            NSLog(@"ipv6 host %@",s);
        }
        
    }
    
}

- (void)connectToNextAddress
{
	BOOL done = NO;
	
	while (!done && ([serverAddresses count] > 0))
	{
		NSData *addr;
		
		// Note: The serverAddresses array probably contains both IPv4 and IPv6 addresses.
		// 
		// If your server is also using GCDAsyncSocket then you don't have to worry about it,
		// as the socket automatically handles both protocols for you transparently.
		
		if (YES) // Iterate forwards
		{
			addr = [serverAddresses objectAtIndex:0];
			[serverAddresses removeObjectAtIndex:0];
		}
		else // Iterate backwards
		{
			addr = [serverAddresses lastObject];
			[serverAddresses removeLastObject];
		}
		
		DDLogVerbose(@"Attempting connection to %@", addr);
		
		NSError *err = nil;
		if ([asyncSocket connectToAddress:addr error:&err])
		{
			done = YES;
		}
		else
		{
			DDLogWarn(@"Unable to connect: %@", err);
		}
		
	}
	
	if (!done)
	{
		DDLogWarn(@"Unable to connect to any resolved address");
	}
}

- (void)socket:(GCDAsyncSocket *)sock didConnectToHost:(NSString *)host port:(UInt16)port
{
	DDLogInfo(@"Socket:DidConnectToHost: %@ Port: %hu", host, port);
	
	connected = YES;
}

- (void)socketDidDisconnect:(GCDAsyncSocket *)sock withError:(NSError *)err
{
	DDLogWarn(@"SocketDidDisconnect:WithError: %@", err);
	
	if (!connected)
	{
		[self connectToNextAddress];
	}
}

@end
