//
//  Recipient.swift
//  SocialGraphKitTests
//
//  Created by Stefano Bertagno on 20/03/21.
//

import Foundation

import SocialGraphKit

extension Recipient.Collection: Reflected {
    /// The prefix.
    public static var debugDescriptionPrefix: String { "Recipient." }
    /// A list of to-be-reflected properties.
    public static let properties: [String: PartialKeyPath<Self>] = ["recipients": \Self.recipients,
                                                                    "error": \Self.error]
}
