<?php

namespace Ds\Bundle\SSOLinkedinBundle\Security\Core\User;

use Ds\Bundle\SSOBundle\Security\Core\User\AbstractOAuthUserProvider;
use HWI\Bundle\OAuthBundle\OAuth\Response\UserResponseInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use RuntimeException;

/**
 * Class LinkedinOAuthUserProvider
 */
class LinkedinOAuthUserProvider extends AbstractOAuthUserProvider
{
    /**
     * {@inheritdoc}
     */
    public function loadUserByOAuthUserResponse(UserResponseInterface $response)
    {
        if (!$this->configManager->get('ds_sso_linkedin.enable_sso')) {
            throw new RuntimeException('SSO is not enabled');
        }

        $username = $response->getUsername();

        if (null === $username) {
            throw new BadCredentialsException('Bad credentials.');
        }

        $property = $response->getResourceOwner()->getName() . '_id';
        $user = $this->userManager->findUserBy([ $property => $username ]);

        if (!$user) {
            $user = $this->userManager->findUserByEmail($response->getEmail());

            if ($user) {
                $user->setLinkedinId($username);
                $this->userManager->updateUser($user);
            }
        }

        if (!$user || !$user->isEnabled()) {
            throw new BadCredentialsException('Bad credentials.');
        }

        return $user;
    }
}
