<?php

declare(strict_types=1);

/**
 * @copyright 2019 Christoph Wurst <christoph@winzerhof-wurst.at>
 *
 * @author 2019 Christoph Wurst <christoph@winzerhof-wurst.at>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace OC\Authentication\Token;

use OC\Authentication\Exceptions\InvalidTokenException;
use OC\Authentication\Exceptions\WipeTokenException;

class RemoteWipe {

	/** @var IProvider */
	private $tokenProvider;

	public function __construct(IProvider $tokenProvider) {
		$this->tokenProvider = $tokenProvider;
	}

	/**
	 * @param string $token
	 *
	 * @return bool whether wiping was started
	 * @throws InvalidTokenException
	 *
	 */
	public function start(string $token): bool {
		try {
			$this->tokenProvider->getToken($token);

			// We expect a WipedTokenException here. If we reach this point this
			// is an ordinary token
			return false;
		} catch (WipeTokenException $e) {
			//TODO: notification+activity that device retrieved the wipe
			return true;
		}
	}

	/**
	 * @param string $token
	 *
	 * @return bool
	 * @throws InvalidTokenException
	 */
	public function finish(string $token): bool {
		try {
			$this->tokenProvider->getToken($token);
		} catch (WipeTokenException $e) {
			//TODO: notification that device has ben wiped
			$this->tokenProvider->invalidateToken($token);
		}
	}

}
