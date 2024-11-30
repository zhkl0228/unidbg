#import <Foundation/Foundation.h>

@protocol OS_nw_path_monitor <NSObject>
@end

typedef NSObject<OS_nw_path_monitor> *nw_path_monitor_t;

typedef enum {
    nw_interface_type_wifi,
    nw_interface_type_cellular,
    nw_interface_type_wired,
    nw_interface_type_loopback,
    nw_interface_type_other
} nw_interface_type_t;

nw_path_monitor_t nw_path_monitor_create_with_type(nw_interface_type_t required_interface_type);

@protocol OS_nw_path <NSObject>
@end

typedef void (^nw_path_monitor_update_handler_t)(NSObject<OS_nw_path> *);
void nw_path_monitor_set_update_handler(nw_path_monitor_t monitor, nw_path_monitor_update_handler_t update_handler);

void nw_path_monitor_set_queue(nw_path_monitor_t monitor, dispatch_queue_t queue);

void nw_path_monitor_start(nw_path_monitor_t monitor);
