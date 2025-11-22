import os
import base64
import json
import re
from PIL import Image, ImageDraw, ImageFont
from openai import OpenAI

# 初始化 OpenAI 客户端
client = OpenAI(
    base_url="https://api-inference.modelscope.cn/v1",
    api_key="",  # ModelScope 令牌
)


def encode_image_to_base64(file_path):
    """将图片编码为 base64 字符串。"""
    try:
        with open(file_path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    except Exception as e:
        print(f"编码 {file_path} 时出错: {e}")
        return None


def parse_json_from_response(response_text):
    """从 API 响应文本中提取并解析 JSON。"""
    try:
        # 从 markdown 代码块中提取 JSON 内容
        json_match = re.search(r"```json\s*(.*?)\s*```", response_text, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
            return json.loads(json_str)
        else:
            # 尝试解析整个响应为 JSON
            return json.loads(response_text)
    except Exception as e:
        print(f"解析 JSON 时出错: {e}")
        return None


def annotate_image(image_path, coordinates, question, output_path):
    """
    使用坐标标记标注图片并保存到输出路径。

    参数:
        image_path: 原始图片路径
        coordinates: 包含坐标的字典列表
        question: 要显示的问题文本
        output_path: 标注后图片的保存路径
    """
    try:
        # 打开图片
        img = Image.open(image_path)
        draw = ImageDraw.Draw(img)

        # 为每个坐标绘制标记
        for idx, coord_data in enumerate(coordinates):
            x, y = None, None

            # 处理不同的坐标格式
            if "x" in coord_data and "y" in coord_data:
                x, y = coord_data["x"], coord_data["y"]
            elif "point_3d" in coord_data:
                point = coord_data["point_3d"]
                x, y = point[0], point[1]

            if x is not None and y is not None:
                # 直接使用原始坐标，不进行偏移
                x_adjusted = x
                y_adjusted = y

                print(
                    f"  原始坐标: ({x}, {y}) -> 使用坐标: ({x_adjusted}, {y_adjusted})"
                )

                # 在调整后的坐标处绘制圆圈
                radius = 15
                draw.ellipse(
                    [
                        x_adjusted - radius,
                        y_adjusted - radius,
                        x_adjusted + radius,
                        y_adjusted + radius,
                    ],
                    outline="red",
                    width=3,
                )

                # 如果存在标签则绘制
                label = coord_data.get("label")
                if label:
                    try:
                        # 尝试加载支持中文的字体
                        font_path = "C:/Windows/Fonts/msyh.ttc"  # 微软雅黑
                        if not os.path.exists(font_path):
                            font_path = "C:/Windows/Fonts/simhei.ttf"  # 黑体

                        if os.path.exists(font_path):
                            font = ImageFont.truetype(font_path, 20)
                        else:
                            font = ImageFont.load_default()
                    except Exception:
                        font = ImageFont.load_default()

                    # 绘制带有背景的文本以提高可见性
                    text_x = x_adjusted + radius + 5
                    text_y = y_adjusted - 10

                    # 获取文本大小以绘制背景
                    bbox = draw.textbbox((text_x, text_y), label, font=font)
                    draw.rectangle(bbox, fill="white")
                    draw.text((text_x, text_y), label, fill="red", font=font)

        # 确保输出目录存在
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # 保存标注后的图片
        img.save(output_path)
        print(f"标注图片已保存至: {output_path}")

    except Exception as e:
        print(f"标注图片时出错: {e}")


def process_images():
    img_dir = os.path.join(os.path.dirname(__file__), "static/img-shape")
    output_dir = os.path.join(os.path.dirname(__file__), "static/img-shape-out")

    if not os.path.exists(img_dir):
        print(f"未找到目录: {img_dir}")
        return

    for filename in os.listdir(img_dir):
        if filename.lower().endswith(".png") and "_regions" not in filename:
            file_path = os.path.join(img_dir, filename)
            print(f"\n正在处理: {filename}")
            print("=" * 60)

            # 将图片编码为 base64
            base64_image = encode_image_to_base64(file_path)
            if not base64_image:
                print("图片编码失败。")
                continue

            # 创建数据 URL
            image_url = f"data:image/png;base64,{base64_image}"
            print("图片编码成功")

            # 调用 API
            try:
                # 首先获取图片尺寸
                with Image.open(file_path) as temp_img:
                    img_width, img_height = temp_img.size
                print(f"图片尺寸: {img_width}x{img_height}")

                response = client.chat.completions.create(
                    model="Qwen/Qwen3-VL-235B-A22B-Instruct",
                    messages=[
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "text",
                                    "text": f'图片尺寸: {img_width}x{img_height}。请完成两个任务：1. 提取图片中的问题文字内容；2. 根据问题找到目标对象，返回其中心点的归一化坐标（坐标系统：左上角(0,0)，右下角(1000,1000)）。返回JSON格式: {{"question": "问题文字", "coordinates": [{{"x": 归一化数字(0-1000), "y": 归一化数字(0-1000), "label": "对象名称"}}]}}',
                                },
                                {
                                    "type": "image_url",
                                    "image_url": {
                                        "url": image_url,
                                    },
                                },
                            ],
                        }
                    ],
                    stream=False,  # 非流式传输以获得更清晰的输出
                )

                response_text = response.choices[0].message.content
                print(f"\nAPI 响应:\n{response_text}")
                print("-" * 60)

                # 解析响应
                parsed_data = parse_json_from_response(response_text)
                if parsed_data:
                    # 提取问题和坐标
                    if isinstance(parsed_data, dict):
                        question = parsed_data.get("question", "")
                        coordinates = parsed_data.get("coordinates", [])
                        if question:
                            print(f"\n📝 问题: {question}")
                    elif isinstance(parsed_data, list):
                        # 旧格式 - 仅坐标
                        coordinates = parsed_data
                        question = ""
                    else:
                        coordinates = []
                        question = ""

                    if coordinates and isinstance(coordinates, list):
                        print(f"📍 原始坐标 (归一化): {coordinates}")

                        # 将归一化坐标转换为绝对像素坐标
                        abs_coordinates = []
                        for coord in coordinates:
                            if "x" in coord and "y" in coord:
                                abs_coord = coord.copy()
                                abs_coord["x"] = int(coord["x"] / 1000 * img_width)
                                abs_coord["y"] = int(coord["y"] / 1000 * img_height)
                                abs_coordinates.append(abs_coord)
                            else:
                                abs_coordinates.append(coord)

                        print(f"📍 绝对坐标: {abs_coordinates}")

                        # 将坐标保存到 'out' 目录下的 JSON 文件中
                        out_dir = os.path.join(
                            os.path.dirname(__file__), "static/img-shape-json"
                        )
                        os.makedirs(out_dir, exist_ok=True)
                        json_filename = os.path.splitext(filename)[0] + ".json"
                        json_path = os.path.join(out_dir, json_filename)

                        with open(json_path, "w", encoding="utf-8") as f:
                            # 保存原始和绝对坐标以供参考
                            save_data = {
                                "raw_response": parsed_data,
                                "absolute_coordinates": abs_coordinates,
                            }
                            json.dump(save_data, f, ensure_ascii=False, indent=2)
                        print(f"坐标已保存至: {json_path}")

                        # 使用绝对坐标标注图片
                        output_path = os.path.join(output_dir, filename)
                        annotate_image(
                            file_path, abs_coordinates, question, output_path
                        )
                    else:
                        print("响应中未找到有效坐标。")
                else:
                    print("解析响应失败。")

            except Exception as e:
                print(f"调用 API 处理 {filename} 时出错: {e}")

            print("=" * 60)


if __name__ == "__main__":
    process_images()
