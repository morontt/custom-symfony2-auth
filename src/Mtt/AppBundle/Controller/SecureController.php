<?php

namespace Mtt\AppBundle\Controller;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;

class SecureController extends Controller
{
    /**
     * @Route("/secure")
     */
    public function indexAction()
    {
        return $this->render('AppBundle:Secure:index.html.twig', []);
    }
}
