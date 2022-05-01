//
//  swift_library.swift
//  swift_library
//
//  Created by Banny on 2022/4/30.
//

import Dispatch

@objcMembers
public class SwiftLibrary : NSObject {

    public func hello() {
        print("Hello, World1")

        let queue = DispatchQueue(label: "queue_test")
        queue.sync {
            print("Queue sync1 Test")
        }
        queue.async {
            print("Queue async Test")
        }
        print("Queue async: queue")
        queue.sync {
            print("Queue sync2 Test")
        }

        print("Hello, World2")
    }

}
