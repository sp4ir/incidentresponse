$sublimebearertoken = ''
$sublimemailboxaddress = ''
$sublimemessagesourceid = ''

function Invoke-SublimeRequest {
    [CmdletBinding()]
    param (
        # Path of the API call to make, not including base hostname. Ex: v1/live-flow/raw-messages/analyze
        [Parameter(Mandatory)]
        [string]$Path,
        # Method for the API call (typically GET or POST)
        [Parameter(Mandatory)]
        [WebRequestMethod]$Method,
        # Content to send to the sublime API, should be in json format alreaady
        [Parameter()]
        [string]$Body
    )
    
    begin {
        $basehostname = 'api.platform.sublimesecurity.com'        
        $url = "https://$basehostname/$Path"
        $headers=@{}
        $headers.Add("accept", "application/json")
        if($Method -eq [WebRequestMethod]'POST') { $headers.Add("content-type", "application/json") }
        $headers.Add("authorization", "Bearer $sublimebearertoken")
    }
    
    process {
        $response = Invoke-WebRequest -Uri $url -Method $Method -Headers $headers -Body $Body
        $response.Content | ConvertFrom-Json -Depth 20
    }
    
    end {
        
    }
}

function Invoke-SublimeAnalyzeMessage {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory)]
        [string]$EmlFile
    )
    
    begin {
        $path = "v1/live-flow/raw-messages/analyze"        

    }
    
    process {
        $emlContent = Get-Content $EmlFile -Raw
        $emlContentInBytes = [System.Text.Encoding]::UTF8.GetBytes($emlContent)
        $emlContentEncoded = [System.Convert]::ToBase64String($emlContentInBytes)
        $body = "{`"mailbox_email_address`":`"$sublimemailboxaddress`",`"message_source_id`":`"$sublimemessagesourceid`",`"raw_message`":`"$emlContentEncoded`"}"
        $message = Invoke-SublimeRequest -Path $path -Method 'POST' -Body $body
        $messageid = $message.message_id
        $messageid
    }
    
    end {
        
    }
}

function Get-SublimeMessageDataModel {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory)]
        [string]$EmlFile
        #$emlfile =  'C:\Users\shawn\Downloads\945508277 - Shawn, your $10 reward certificate has arrived..eml'
    )
    
    begin {
        $path = "v1/live-flow/raw-messages/analyze"        
    }
    
    process {
        $messageid = Invoke-SublimeAnalyzeMessage -EmlFile $emlfile
        $messageid
        $path = "v0/messages/$messageid/message_data_model"
        $messagedatamodel = Invoke-SublimeRequest -Path $path -Method 'GET'
        $messagedatamodel
    }
    
    end {
        
    }
}