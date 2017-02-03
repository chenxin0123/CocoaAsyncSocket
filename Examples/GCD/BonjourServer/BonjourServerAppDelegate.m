#import "BonjourServerAppDelegate.h"
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


@implementation BonjourServerAppDelegate

@synthesize window;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
	// Configure logging framework
	
	[DDLog addLogger:[DDTTYLogger sharedInstance]];
	[DDLog addLogger:[DDASLLogger sharedInstance]];
	
	// Create our socket.
	// We tell it to invoke our delegate methods on the main thread.
	
	asyncSocket = [[GCDAsyncSocket alloc] initWithDelegate:self delegateQueue:dispatch_get_main_queue()];
	
	// Create an array to hold accepted incoming connections.
	
	connectedSockets = [[NSMutableArray alloc] init];
	
	// Now we tell the socket to accept incoming connections.
	// We don't care what port it listens on, so we pass zero for the port number.
	// This allows the operating system to automatically assign us an available port.
	
	NSError *err = nil;
	if ([asyncSocket acceptOnPort:0 error:&err])
	{
		// So what port did the OS give us?
		
		UInt16 port = [asyncSocket localPort];
		
		// Create and publish the bonjour service.
		// Obviously you will be using your own custom service type.
		
		netService = [[NSNetService alloc] initWithDomain:@"local."
		                                             type:@"_YourServiceName._tcp."
		                                             name:@""
		                                             port:port];
		
		[netService setDelegate:self];
		[netService publish];
		
		// You can optionally add TXT record stuff
		
		NSMutableDictionary *txtDict = [NSMutableDictionary dictionaryWithCapacity:2];
		
		[txtDict setObject:@"moo" forKey:@"cow"];
		[txtDict setObject:@"quack" forKey:@"duck"];
		
		NSData *txtData = [NSNetService dataFromTXTRecordDictionary:txtDict];
		[netService setTXTRecordData:txtData];
	}
	else
	{
		DDLogError(@"Error in acceptOnPort:error: -> %@", err);
	}
}

- (void)socket:(GCDAsyncSocket *)sock didAcceptNewSocket:(GCDAsyncSocket *)newSocket
{
	DDLogInfo(@"Accepted new socket from %@:%hu", [newSocket connectedHost], [newSocket connectedPort]);
	
	// The newSocket automatically inherits its delegate & delegateQueue from its parent.
	
	[connectedSockets addObject:newSocket];
    [self outputHosts];
}

- (void)socketDidDisconnect:(GCDAsyncSocket *)sock withError:(NSError *)err
{
	[connectedSockets removeObject:sock];
}

- (void)netServiceDidPublish:(NSNetService *)ns
{
	NSLog(@"Bonjour Service Published: domain(%@) type(%@) name(%@) port(%i)",
			  [ns domain], [ns type], [ns name], (int)[ns port]);
}

- (void)outputHosts {
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

- (void)netService:(NSNetService *)ns didNotPublish:(NSDictionary *)errorDict
{
	// Override me to do something here...
	// 
	// Note: This method in invoked on our bonjour thread.
	
	DDLogError(@"Failed to Publish Service: domain(%@) type(%@) name(%@) - %@",
				[ns domain], [ns type], [ns name], errorDict);
}

@end
