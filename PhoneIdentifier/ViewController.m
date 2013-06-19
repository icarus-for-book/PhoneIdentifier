//
//  ViewController.m
//  PhoneIdentifier
//
//  Created by jinni ahn on 6/19/13.
//  Copyright (c) 2013 SDS. All rights reserved.
//

#import "ViewController.h"
#import <CommonCrypto/CommonDigest.h>
#import <AdSupport/AdSupport.h>
#import "KeychainItemWrapper.h"
#import "OpenUDID.h" // OpenUDID

#include <sys/socket.h> // Per msqr
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>


NS_ENUM(NSInteger, kMethod){
    kMethodUDID,
    kMethodCFUUIDCreate,
    kMethodMacaddress,
    kMethodAppsfire,
    kMethodiOS6UIDevice,
    kMethodiOS6ASIdentifier
};

@interface ViewController () <UITableViewDataSource, UITableViewDelegate >
@property (retain, nonatomic) IBOutlet UITableView *tableView;
@property (retain, nonatomic) NSArray *data;

@end

@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
    
    self.title = @"UDID 만드는 방법";
    
    self.data = @[ @{@"title": @"UIDevice 사용"},
                   @{@"title": @"CFUUIDCreate 사용"},
                   @{@"title": @"Wifi Mac Address 사용"},
                   @{@"title": @"Appsfire-OpenUDID 라이브러리 사용"},
                   @{@"title": @"iOS6의 UIDevice 사용"},
                   @{@"title": @"iOS6의 ASIdentifierManager 사용"}];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)dealloc {
    [_tableView release];
    [super dealloc];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView
{
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return self.data.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    NSString *cellName = @"Cell";
    
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cellName];
    if (cell == nil) {
        cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:cellName] autorelease];
    }

    NSDictionary *info = [self.data objectAtIndex:indexPath.row];
    NSString *title = [info objectForKey:@"title"];
    NSString *udid = @"xxx";
    
    

    if( indexPath.row == kMethodUDID)
    {
        udid = [self udidUsingUIDevice];
    } else if( indexPath.row == kMethodCFUUIDCreate)
    {
        udid = [self udidUsingCFUUID];
    } else if( indexPath.row == kMethodMacaddress)
    {
        udid = [self udidUsingMacAddress];
        
    } else if( indexPath.row == kMethodAppsfire)
    {
        udid = [self udidUsingAppsfire];
        
    } else if( indexPath.row == kMethodiOS6UIDevice)
    {
        udid = [self udidUsingiOS6UIDevice];
        
    } else if( indexPath.row == kMethodiOS6ASIdentifier)
    {
        udid = [self udidUsingiOS6ASIdentifier];
    }
    
    cell.textLabel.text = title;
    cell.detailTextLabel.text = udid;
    
    return cell;
}


- (NSString*) udidUsingCFUUID
{
    // initialize keychaing item for saving UUID.
    KeychainItemWrapper *wrapper = [[KeychainItemWrapper alloc] initWithIdentifier:@"UUID"
                                                                       accessGroup:nil];
    
    NSString *uuid = [wrapper objectForKey:kSecAttrAccount];
    if( uuid == nil || uuid.length == 0)
    {

        // if there is not UUID in keychain, make UUID and save it.
        CFUUIDRef uuidRef = CFUUIDCreate(NULL);
        CFStringRef uuidStringRef = CFUUIDCreateString(NULL, uuidRef);
        CFRelease(uuidRef);
        uuid = [NSString stringWithString:(NSString *) uuidStringRef];
        CFRelease(uuidStringRef);

        // save UUID in keychain
        [wrapper setObject:uuid forKey:kSecAttrAccount];
    }
    
    return uuid;
}
- (NSString*) udidUsingMacAddress
{
    // can use up to  iOS 6.0 and before
    // mac address from system in iOS 7 and later will be
    // '02:00:00:00:00:00
    NSString *macaddr = [self getMacAddress];
    
    // hash |macaddr| using SHA1 to make udid which is 40 long.
    const char *ptr = [macaddr UTF8String];
    unsigned char buf[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(ptr, strlen(ptr), buf);
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x",buf[i]];
    NSString *uuid = [NSString stringWithString:output];
    
    return uuid;
}
- (NSString*) udidUsingAppsfire
{
    NSString* openUDID = [OpenUDID value];
    return openUDID;
}
- (NSString*) udidUsingiOS6UIDevice
{
    // can use iOS 6.0 and later
    return [[[UIDevice currentDevice] identifierForVendor] UUIDString];
}
- (NSString*) udidUsingiOS6ASIdentifier
{
    // can use iOS 6.0 and later
    ASIdentifierManager *manager = [ASIdentifierManager sharedManager];
    return [[manager advertisingIdentifier] UUIDString];
}


// This is a way to use UIDevice API. this is deprecated since iOS5.
// so, you cannot use anymore if you want to upload to Apple AppStore.
- (NSString*) udidUsingUIDevice
{
    return [[UIDevice currentDevice] uniqueIdentifier];
}


//
// from https://gist.github.com/Coeur/1409855
//
- (NSString *)getMacAddress
{
    int                 mgmtInfoBase[6];
    char                *msgBuffer = NULL;
    NSString            *errorFlag = NULL;
    size_t              length;
    
    // Setup the management Information Base (mib)
    mgmtInfoBase[0] = CTL_NET;        // Request network subsystem
    mgmtInfoBase[1] = AF_ROUTE;       // Routing table info
    mgmtInfoBase[2] = 0;
    mgmtInfoBase[3] = AF_LINK;        // Request link layer information
    mgmtInfoBase[4] = NET_RT_IFLIST;  // Request all configured interfaces
    
    // With all configured interfaces requested, get handle index
    if ((mgmtInfoBase[5] = if_nametoindex("en0")) == 0)
        errorFlag = @"if_nametoindex failure";
    // Get the size of the data available (store in len)
    else if (sysctl(mgmtInfoBase, 6, NULL, &length, NULL, 0) < 0)
        errorFlag = @"sysctl mgmtInfoBase failure";
    // Alloc memory based on above call
    else if ((msgBuffer = malloc(length)) == NULL)
        errorFlag = @"buffer allocation failure";
    // Get system information, store in buffer
    else if (sysctl(mgmtInfoBase, 6, msgBuffer, &length, NULL, 0) < 0)
    {
        free(msgBuffer);
        errorFlag = @"sysctl msgBuffer failure";
    }
    else
    {
        // Map msgbuffer to interface message structure
        struct if_msghdr *interfaceMsgStruct = (struct if_msghdr *) msgBuffer;
        
        // Map to link-level socket structure
        struct sockaddr_dl *socketStruct = (struct sockaddr_dl *) (interfaceMsgStruct + 1);
        
        // Copy link layer address data in socket structure to an array
        unsigned char macAddress[6];
        memcpy(&macAddress, socketStruct->sdl_data + socketStruct->sdl_nlen, 6);
        
        // Read from char array into a string object, into traditional Mac address format
        NSString *macAddressString = [NSString stringWithFormat:@"%02X:%02X:%02X:%02X:%02X:%02X",
                                      macAddress[0], macAddress[1], macAddress[2], macAddress[3], macAddress[4], macAddress[5]];
        NSLog(@"Mac Address: %@", macAddressString);
        
        // Release the buffer memory
        free(msgBuffer);
        
        return macAddressString;
    }
    
    // Error...
    NSLog(@"Error: %@", errorFlag);
    
    return nil;
}


@end
