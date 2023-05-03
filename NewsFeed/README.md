# How to Use

1. Install the content pack on your Graylog server as detailed within: [Content Packs](https://go2docs.graylog.org/5-0/what_more_can_graylog_do_for_me/content_packs.html)

2. Create an individual index set for the newsFeew (best practice, but not required) - [Indices](https://go2docs.graylog.org/5-0/setting_up_graylog/index_model.html)

3. Set the NewFeed stream to route to the new index set by editing it, this will prevent any mapping conflicts.

![image](https://user-images.githubusercontent.com/28361907/235950358-cede169c-b3e3-4f0a-866e-a48842006a73.png)

4. Place python script and requirements.txt in the desired location/host 

5. Install the requirements for the python script like ```python3 -m pip install -r requirements.txt```

6. Edit the variables at the top of the python script and add any additional RSS feed you desire.

![image](https://user-images.githubusercontent.com/28361907/235951094-fec61559-c6d8-474c-93e3-fa96b36d79cb.png)


7.. Run the python script ```python3 secNews.py```
