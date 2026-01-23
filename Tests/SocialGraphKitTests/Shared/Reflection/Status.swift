//
//  Status.swift
//  SocialGraphKitTests
//
//  Created by Stefano Bertagno on 20/03/21.
//

import Foundation

import SocialGraphKit

extension Status: Reflected {
    /// The debug description prefix.
    public static let debugDescriptionPrefix: String = ""
    /// A list of to-be-reflected properties.
    public static let properties: [String: PartialKeyPath<Self>] = ["error": \Self.error]
}
