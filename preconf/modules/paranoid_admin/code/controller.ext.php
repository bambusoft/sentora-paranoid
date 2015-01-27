<?php

# Unofficial Sentora Automated Security Module
# =============================================
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#  Official website: http://sentora-paranoid.open-source.tk
#
#  Author Mario Rodriguez Somohano, sentora-paranoid (at) open-source.tk
# 

class module_controller extends ctrl_module {

    static $ok;
	
    static function getParanoidConfig()
    {
        $display = self::DisplayParanoidConfig();
        return $display;
    }
	
    static function DisplayParanoidConfig()
    {
        global $zdbh;
        global $controller;
		
		$line = "<style>.active {color: #333;}</style>";
		$line .= "<h2>" . ui_language::translate("Configure your security settings") . "</h2>";
		$line .= "<div style=\"display: block; margin-right:20px;\">";
		$line .= "<div class=\"ui-tabs ui-widget ui-widget-content ui-corner-all\" id=\"paranoidTabs\">";
		$line .= "<ul class=\"domains nav nav-tabs\">";
		$line .= "<li class=\"active\"><a href=\"#general\" data-toggle=\"tab\">" . ui_language::translate("General") . "</a></li>";
		//$line .= "<li><a href=\"#ipblacklist\" data-toggle=\"tab\">" . ui_language::translate("IPBlackList") . "</a></li>";
		$line .= "<li><a href=\"#firewall\" data-toggle=\"tab\">" . ui_language::translate("Firewall") . "</a></li>";
		$line .= "</ul>";

		//Tabs Panel Wrap
		$line .= '<div class="tab-content">';

		//general
		$line .= "<div class=\"tab-pane active\" id=\"general\">";
		$line .= "<form action=\"./?module=dns_admin&action=UpdateDNSConfig\" method=\"post\">";
		$line .= "<table class=\"table table-striped\">";

		$line .= "<tr valign=\"top\"><th nowrap=\"nowrap\">" . ui_language::translate("temp") . "</th><td>" . $temp . "</td><td>" . ui_language::translate("desc") . "</td></tr>";

		$line .= "<tr><th colspan=\"3\"><button class=\"button-loader btn btn-primary\" type=\"submit\" id=\"button\" name=\"inSaveSystem\">" . ui_language::translate("Save Changes") . "</button>  <button class=\"button-loader btn btn-default\" type=\"button\" onclick=\"window.location.href='./?module=moduleadmin';return false;\">" . ui_language::translate("Cancel") . "</button></tr>";
		$line .= "</table>";
		$line .= "</form>";
		$line .= "</div>";
		
         //firewall
        $line .= "<div class=\"tab-pane\" id=\"firewall\">";
        $line .= "<form action=\"./?module=paranoid_admin&action=UpdateFirewall\" method=\"post\">";
        $line .= "<table class=\"none\" border=\"0\" cellpading=\"0\" cellspacing=\"0\" width=\"85%\"><tr valign=\"top\"><td width=\"100%\">";
        $line .= "<table class=\"table table-striped\">";
        $line .= "<tr>";
        $line .= "<th>" . ui_language::translate("Restore firewall") . "</th>";
        $line .= "<td><button class=\"button-loader btn btn-primary\" type=\"submit\" id=\"button\" name=\"inRestartFirewall\" value=\"1\">" . ui_language::translate("GO") . "</button></td>";
        $line .= "</tr>";

        $line .= "</table>";
 
        $line .="</td></tr></table>";
        $line .= "</form>";
        $line .= "</div>";
		
	}
	
   static function getResult()
    {
        if (!fs_director::CheckForEmptyValue(self::$ok)) {
            return ui_sysmessage::shout(ui_language::translate("Changes to your settings have been saved successfully!"), "zannounceok");
        }
	}
}
